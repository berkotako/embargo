//! Sandboxed install runner. Forks a child that enters a user namespace (for
//! CAP_SYS_ADMIN, so it can install a user-notify filter) plus pid/mount
//! namespaces for isolation, installs the `connect()` filter, hands the
//! listener fd back to the parent, and execs the install command. The parent
//! supervises egress and reaps the child.

use crate::allowlist::Allowlist;
use crate::chain::{ChainDetection, ChainDetector};
use crate::seccomp::{self, BlockedEgress, SupervisorEvent};
use anyhow::{bail, Context, Result};
use nix::sys::socket::{
    recvmsg, sendmsg, socketpair, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags,
    SockFlag, SockType,
};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::ffi::CString;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// Outcome of a sandboxed run.
#[derive(Debug)]
pub struct RunOutcome {
    pub exit_code: i32,
    pub blocked: Vec<BlockedEgress>,
    pub chains: Vec<ChainDetection>,
}

pub struct RunConfig {
    pub allow: Allowlist,
    /// argv of the install command, e.g. ["npm", "ci"].
    pub command: Vec<String>,
    /// Isolate via user+pid+mount namespaces (best-effort; required for the
    /// user-notify listener to install unprivileged).
    pub isolate: bool,
    /// Enable runtime compromise-chain detection (also observes openat()).
    pub detect_chain: bool,
    /// Chain correlation window (secret-read → egress) in milliseconds.
    pub chain_window_ms: u64,
}

/// Run the command under egress supervision. `on_event` is invoked for each
/// blocked egress and chain detection (the binary wires this to ReportEvent).
pub fn run(cfg: &RunConfig, mut on_event: impl FnMut(&SupervisorEvent)) -> Result<RunOutcome> {
    if cfg.command.is_empty() {
        bail!("empty command");
    }
    seccomp::check_abi().context("kernel seccomp user-notify ABI")?;

    // Socketpair to pass the listener fd from child to parent.
    let (parent_sock, child_sock) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None,
        SockFlag::empty(),
    )
    .context("socketpair")?;

    // SAFETY: fork(); the child path only calls async-signal-safe-ish setup and
    // then execvp. We keep the child path short and panic-free where possible.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Child => {
            drop(parent_sock);
            child_main(cfg, child_sock); // diverges (execs or _exit)
        }
        ForkResult::Parent { child } => {
            drop(child_sock);
            let listener = recv_fd(parent_sock.as_raw_fd()).context("receive listener fd")?;
            let mut blocked = Vec::new();
            let mut chains = Vec::new();
            let mut detector = cfg
                .detect_chain
                .then(|| ChainDetector::new(cfg.chain_window_ms));
            seccomp::supervise(listener.as_raw_fd(), &cfg.allow, detector.as_mut(), |ev| {
                on_event(&ev);
                match ev {
                    SupervisorEvent::Blocked(b) => blocked.push(b),
                    SupervisorEvent::Chain(c) => chains.push(c),
                }
            })?;
            let exit_code = reap(child)?;
            Ok(RunOutcome {
                exit_code,
                blocked,
                chains,
            })
        }
    }
}

/// Child: enter namespaces, install the filter, send the fd, exec the command.
fn child_main(cfg: &RunConfig, child_sock: OwnedFd) -> ! {
    if cfg.isolate {
        if let Err(e) = enter_user_namespace() {
            eprintln!("embargo-sandbox: namespace setup failed: {e}");
            unsafe { libc::_exit(126) };
        }
    }

    let listener = match seccomp::install_notify_filter(cfg.detect_chain) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("embargo-sandbox: seccomp install failed: {e}");
            unsafe { libc::_exit(126) };
        }
    };

    if let Err(e) = send_fd(child_sock.as_raw_fd(), listener) {
        eprintln!("embargo-sandbox: send fd failed: {e}");
        unsafe { libc::_exit(126) };
    }
    drop(child_sock);

    // Bound the blast radius of a malicious install (fork bomb, disk fill,
    // memory/CPU exhaustion) before handing control to it.
    apply_rlimits();

    // exec the install command; from here the seccomp filter governs connect().
    // CString::new fails only on an interior NUL byte; in the post-fork child we
    // must never panic (it would unwind across the fork), so _exit instead.
    let prog = match CString::new(cfg.command[0].clone()) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("embargo-sandbox: command contains an interior NUL byte");
            unsafe { libc::_exit(126) };
        }
    };
    let mut argv: Vec<CString> = Vec::with_capacity(cfg.command.len());
    for a in &cfg.command {
        match CString::new(a.clone()) {
            Ok(c) => argv.push(c),
            Err(_) => {
                eprintln!("embargo-sandbox: argument contains an interior NUL byte");
                unsafe { libc::_exit(126) };
            }
        }
    }
    let _ = execvp(&prog, &argv);
    eprintln!("embargo-sandbox: exec {} failed", cfg.command[0]);
    unsafe { libc::_exit(127) };
}

/// Best-effort resource caps applied in the child before exec. These bound a
/// runaway/malicious install so it can't take down the host: a fork bomb, a
/// disk-filling write, or memory/CPU exhaustion. We only ever lower a limit
/// (clamped to the existing hard limit) and never fail the run if a cap can't be
/// set — this is defense in depth layered on the egress filter and namespaces.
fn apply_rlimits() {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    const GIB: u64 = 1024 * 1024 * 1024;
    // (resource, desired soft cap). Generous enough for a real `npm ci`.
    let caps = [
        (Resource::RLIMIT_NPROC, 1024), // processes/threads — fork-bomb guard
        (Resource::RLIMIT_AS, 4 * GIB), // address space — memory guard
        (Resource::RLIMIT_FSIZE, 4 * GIB), // max file size — disk-fill guard
        (Resource::RLIMIT_CPU, 900),    // CPU seconds — runaway guard
        (Resource::RLIMIT_NOFILE, 4096), // open file descriptors
    ];
    for (res, desired) in caps {
        if let Ok((_, hard)) = getrlimit(res) {
            let soft = desired.min(hard); // never exceed the hard limit
            if let Err(e) = setrlimit(res, soft, hard) {
                eprintln!("embargo-sandbox: setrlimit({res:?}) failed (continuing): {e}");
            }
        }
    }
}

/// Enter a new user namespace mapping the current uid/gid to root (granting
/// CAP_SYS_ADMIN inside it), plus pid+mount namespaces for isolation.
fn enter_user_namespace() -> Result<()> {
    use nix::sched::{unshare, CloneFlags};
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();

    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID)
        .context("unshare(user|mount|pid)")?;

    // Map our outer uid/gid to root inside the new userns.
    std::fs::write("/proc/self/setgroups", b"deny").ok();
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).context("write uid_map")?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).context("write gid_map")?;
    Ok(())
}

fn reap(child: Pid) -> Result<i32> {
    match waitpid(child, None).context("waitpid")? {
        WaitStatus::Exited(_, code) => Ok(code),
        WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
        other => bail!("unexpected child status: {other:?}"),
    }
}

// ---- SCM_RIGHTS fd passing --------------------------------------------------

fn send_fd(sock: RawFd, fd: RawFd) -> Result<()> {
    let iov = [IoSlice::new(b"x")];
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(sock, &iov, &cmsg, MsgFlags::empty(), None).context("sendmsg fd")?;
    Ok(())
}

fn recv_fd(sock: RawFd) -> Result<OwnedFd> {
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(sock, &mut iov, Some(&mut cmsg_space), MsgFlags::empty())
        .context("recvmsg fd")?;
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                // SAFETY: fd was just received via SCM_RIGHTS and is owned by us.
                return Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) });
            }
        }
    }
    bail!("no fd in control message")
}
