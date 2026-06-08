//! seccomp `connect()` interception via user-notification.
//!
//! A classic-BPF seccomp filter returns `SECCOMP_RET_USER_NOTIF` for `connect`
//! and `SECCOMP_RET_ALLOW` for everything else. The kernel hands the install
//! a *listener fd*; a supervisor reads each pending `connect()`, parses the
//! destination from the target's memory, and either lets it continue
//! (allowlisted / loopback) or fails it with `EPERM` and captures it.
//!
//! This is the one crate permitted `unsafe`. Every `unsafe` block below is a
//! raw syscall/ioctl against a stable kernel ABI and carries a justification.

use crate::allowlist::{self, Allowlist, Decision};
use crate::chain::{self, ChainDetection, ChainDetector, EventKind, RuntimeEvent};
use anyhow::{bail, Context, Result};
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::time::Instant;

// ---- ABI constants (linux/seccomp.h, linux/filter.h, linux/audit.h) --------

const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_GET_NOTIF_SIZES: libc::c_uint = 3;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const NR_CONNECT_X86_64: u32 = 42;
const NR_OPENAT_X86_64: u32 = 257;

// Classic BPF opcodes.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

// Offsets into struct seccomp_data.
const SD_NR_OFF: u32 = 0;
const SD_ARCH_OFF: u32 = 4;

/// Build the notify seccomp program. `notify_openat` adds openat() to the set
/// of syscalls forwarded to the supervisor (for runtime secret-read detection).
/// Pure — unit-testable.
pub fn build_notify_program(notify_openat: bool) -> Vec<libc::sock_filter> {
    if !notify_openat {
        // 0: load arch
        // 1: if arch != x86_64 -> KILL (idx 6)
        // 2: load nr
        // 3: if nr != connect -> ALLOW (idx 5)
        // 4: USER_NOTIF / 5: ALLOW / 6: KILL
        return vec![
            stmt(BPF_LD_W_ABS, SD_ARCH_OFF),
            jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 0, 4),
            stmt(BPF_LD_W_ABS, SD_NR_OFF),
            jump(BPF_JEQ_K, NR_CONNECT_X86_64, 0, 1),
            stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF),
            stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
            stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        ];
    }
    // 0: load arch
    // 1: if arch != x86_64 -> KILL (idx 7)
    // 2: load nr
    // 3: if nr == connect -> USER_NOTIF (idx 5)
    // 4: if nr == openat  -> USER_NOTIF (idx 5) else ALLOW (idx 6)
    // 5: USER_NOTIF / 6: ALLOW / 7: KILL
    vec![
        stmt(BPF_LD_W_ABS, SD_ARCH_OFF),
        jump(BPF_JEQ_K, AUDIT_ARCH_X86_64, 0, 5),
        stmt(BPF_LD_W_ABS, SD_NR_OFF),
        jump(BPF_JEQ_K, NR_CONNECT_X86_64, 1, 0),
        jump(BPF_JEQ_K, NR_OPENAT_X86_64, 0, 1),
        stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
    ]
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Install the filter and return the user-notification listener fd.
/// Caller must already hold CAP_SYS_ADMIN (e.g. inside a user namespace).
/// `notify_openat` also forwards openat() for runtime secret-read detection.
pub fn install_notify_filter(notify_openat: bool) -> Result<RawFd> {
    // no_new_privs lets an unprivileged-in-userns process install a filter.
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes scalar args; no pointers.
    let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("prctl(NO_NEW_PRIVS)");
    }

    let prog = build_notify_program(notify_openat);
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: seccomp(SET_MODE_FILTER, NEW_LISTENER, &fprog) — fprog points to a
    // valid, correctly-sized filter that outlives the call. With NEW_LISTENER
    // the return value is the listener fd (>= 0) rather than 0.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const libc::sock_fprog,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("seccomp(NEW_LISTENER)");
    }
    Ok(fd as RawFd)
}

// ---- Notification structs (must match the kernel ABI exactly) --------------

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: libc::c_int,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SeccompNotifSizes {
    seccomp_notif: u16,
    seccomp_notif_resp: u16,
    seccomp_data: u16,
}

// ioctl request numbers: _IOWR('!', n, struct) / _IOW('!', n, u64).
const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;
const SECCOMP_IOC_MAGIC: u64 = b'!' as u64;

const fn ioc(dir: u64, nr: u64, size: u64) -> libc::c_ulong {
    ((dir << 30) | (SECCOMP_IOC_MAGIC << 8) | nr | (size << 16)) as libc::c_ulong
}

fn ioctl_recv() -> libc::c_ulong {
    ioc(
        IOC_READ | IOC_WRITE,
        0,
        std::mem::size_of::<SeccompNotif>() as u64,
    )
}
fn ioctl_send() -> libc::c_ulong {
    ioc(
        IOC_READ | IOC_WRITE,
        1,
        std::mem::size_of::<SeccompNotifResp>() as u64,
    )
}
fn ioctl_id_valid() -> libc::c_ulong {
    ioc(IOC_WRITE, 2, std::mem::size_of::<u64>() as u64)
}

/// Verify our struct layouts match the running kernel before we trust them.
pub fn check_abi() -> Result<()> {
    let mut sizes = SeccompNotifSizes::default();
    // SAFETY: seccomp(GET_NOTIF_SIZES) writes three u16 into the provided struct.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_NOTIF_SIZES,
            0,
            &mut sizes as *mut SeccompNotifSizes,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("seccomp(GET_NOTIF_SIZES)");
    }
    if sizes.seccomp_notif as usize != std::mem::size_of::<SeccompNotif>()
        || sizes.seccomp_notif_resp as usize != std::mem::size_of::<SeccompNotifResp>()
        || sizes.seccomp_data as usize != std::mem::size_of::<SeccompData>()
    {
        bail!(
            "seccomp notif ABI mismatch: kernel {}/{}/{} vs built {}/{}/{}",
            sizes.seccomp_notif,
            sizes.seccomp_notif_resp,
            sizes.seccomp_data,
            std::mem::size_of::<SeccompNotif>(),
            std::mem::size_of::<SeccompNotifResp>(),
            std::mem::size_of::<SeccompData>(),
        );
    }
    Ok(())
}

/// A captured blocked egress attempt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockedEgress {
    pub pid: u32,
    pub dest: SocketAddr,
}

/// What the supervisor surfaces to the caller.
pub enum SupervisorEvent {
    /// A non-allowlisted egress was blocked with EPERM.
    Blocked(BlockedEgress),
    /// A runtime compromise chain completed (secret read → non-allowlisted egress).
    Chain(ChainDetection),
}

const NR_CONNECT: i32 = NR_CONNECT_X86_64 as i32;
const NR_OPENAT: i32 = NR_OPENAT_X86_64 as i32;

/// Run the supervisor loop on `listener`, enforcing `allow`. When `chain` is
/// Some, openat() is also observed (the filter must have been installed with
/// `notify_openat = true`) and the detector correlates secret-read → egress.
/// `on_event` receives blocked egresses and chain detections. Returns when the
/// target has exited (RECV fails).
pub fn supervise(
    listener: RawFd,
    allow: &Allowlist,
    mut chain: Option<&mut ChainDetector>,
    mut on_event: impl FnMut(SupervisorEvent),
) -> Result<()> {
    let recv = ioctl_recv();
    let send = ioctl_send();
    let id_valid = ioctl_id_valid();
    let start = Instant::now();

    loop {
        let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
        // SAFETY: NOTIF_RECV blocks until a syscall is pending or the target
        // dies; it fills `notif`. A nonzero return ends or retries the loop.
        let rc = unsafe { libc::ioctl(listener, recv, &mut notif as *mut SeccompNotif) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                // ENOENT here means the only target exited — clean shutdown.
                Some(libc::ENOENT) => return Ok(()),
                _ => return Err(err).context("NOTIF_RECV"),
            }
        }

        let at_ms = start.elapsed().as_millis() as u64;
        let mut resp = SeccompNotifResp {
            id: notif.id,
            ..Default::default()
        };

        match notif.data.nr {
            NR_CONNECT => {
                let dest = read_dest(notif.pid, &notif.data);
                // Validate the id before trusting the memory we read.
                // SAFETY: NOTIF_ID_VALID reads one u64; 0 = still valid.
                if unsafe { libc::ioctl(listener, id_valid, &notif.id as *const u64) } != 0 {
                    continue;
                }
                let decision = allowlist::decide(allow, dest);
                match decision {
                    Decision::Allow => resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                    Decision::Block => {
                        resp.error = -libc::EPERM;
                        if let Some(d) = dest {
                            on_event(SupervisorEvent::Blocked(BlockedEgress {
                                pid: notif.pid,
                                dest: d,
                            }));
                        }
                    }
                }
                if let (Some(det), Some(d)) = (chain.as_deref_mut(), dest) {
                    let ev = RuntimeEvent {
                        pid: notif.pid,
                        at_ms,
                        kind: EventKind::Egress {
                            dest: d,
                            allowlisted: decision == Decision::Allow,
                        },
                    };
                    if let Some(hit) = det.observe(&ev) {
                        on_event(SupervisorEvent::Chain(hit));
                    }
                }
            }
            NR_OPENAT => {
                // Observe-only: always allow the open; record secret reads.
                let path = read_path(notif.pid, &notif.data);
                // SAFETY: NOTIF_ID_VALID reads one u64; 0 = still valid.
                if unsafe { libc::ioctl(listener, id_valid, &notif.id as *const u64) } != 0 {
                    continue;
                }
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                if let (Some(det), Some(p)) = (chain.as_deref_mut(), path) {
                    if chain::is_secret_path(&p) {
                        let ev = RuntimeEvent {
                            pid: notif.pid,
                            at_ms,
                            kind: EventKind::SecretRead { path: p },
                        };
                        let _ = det.observe(&ev); // a read alone never completes a chain
                    }
                }
            }
            _ => {
                // The filter only notifies connect/openat; allow anything else.
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            }
        }

        // SAFETY: NOTIF_SEND consumes `resp` (matching the recv'd id).
        let rc = unsafe { libc::ioctl(listener, send, &resp as *const SeccompNotifResp) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // The target may have died between recv and send; ignore and continue.
            if matches!(err.raw_os_error(), Some(libc::ENOENT)) {
                continue;
            }
            return Err(err).context("NOTIF_SEND");
        }
    }
}

/// Read the openat() pathname (a C string at args[1]) from the target's memory.
fn read_path(pid: u32, data: &SeccompData) -> Option<String> {
    let ptr = data.args[1] as usize;
    if ptr == 0 {
        return None;
    }
    let mut buf = vec![0u8; 256];
    let read = {
        let local = IoSliceMut::new(&mut buf);
        let remote = nix::sys::uio::RemoteIoVec {
            base: ptr,
            len: 256,
        };
        nix::sys::uio::process_vm_readv(
            nix::unistd::Pid::from_raw(pid as i32),
            &mut [local],
            &[remote],
        )
        .ok()?
    };
    let bytes = &buf[..read];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

/// Read and parse the `connect()` destination sockaddr from the target's memory.
/// args[1] = sockaddr pointer, args[2] = addrlen (in the target address space).
fn read_dest(pid: u32, data: &SeccompData) -> Option<SocketAddr> {
    let addr_ptr = data.args[1] as usize;
    let addr_len = (data.args[2] as usize).min(128); // cap to sizeof(sockaddr_storage)
    if addr_ptr == 0 || addr_len < 2 {
        return None;
    }

    let mut buf = vec![0u8; addr_len];
    let local = IoSliceMut::new(&mut buf);
    let remote = nix::sys::uio::RemoteIoVec {
        base: addr_ptr,
        len: addr_len,
    };
    let read = nix::sys::uio::process_vm_readv(
        nix::unistd::Pid::from_raw(pid as i32),
        &mut [local],
        &[remote],
    )
    .ok()?;
    allowlist::parse_sockaddr(&buf[..read])
}

/// Best-effort: turn a hostname or IP allow-spec into IPs by resolving now.
/// (connect() only ever sees IPs, so the allowlist must be IP-based.)
pub fn resolve_allow_specs(specs: &[String]) -> Result<Allowlist> {
    use std::net::ToSocketAddrs;
    let mut ips = Vec::new();
    for spec in specs {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        if let Ok(ip) = spec.parse::<std::net::IpAddr>() {
            ips.push(ip);
        } else {
            // Resolve hostname → IPs (append :0 so the resolver accepts it).
            let resolved = format!("{spec}:0")
                .to_socket_addrs()
                .with_context(|| format!("resolving allow host {spec}"))?;
            ips.extend(resolved.map(|s| s.ip()));
        }
    }
    if ips.is_empty() {
        return Ok(Allowlist::default());
    }
    Ok(Allowlist::new(ips))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_only_program_has_expected_shape() {
        let p = build_notify_program(false);
        assert_eq!(p.len(), 7);
        assert_eq!(p[4].code, BPF_RET_K);
        assert_eq!(p[4].k, SECCOMP_RET_USER_NOTIF);
        assert_eq!(p[5].k, SECCOMP_RET_ALLOW);
        assert_eq!(p[6].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn openat_program_adds_a_branch() {
        let p = build_notify_program(true);
        assert_eq!(p.len(), 8);
        // connect → USER_NOTIF, openat → USER_NOTIF, else ALLOW.
        assert_eq!(p[5].k, SECCOMP_RET_USER_NOTIF);
        assert_eq!(p[6].k, SECCOMP_RET_ALLOW);
        assert_eq!(p[7].k, SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn ioctl_numbers_are_stable() {
        // Spot-check the encoded request numbers against known-good constants
        // for x86_64 (sizeof SeccompNotif = 80, Resp = 24).
        assert_eq!(std::mem::size_of::<SeccompNotif>(), 80);
        assert_eq!(std::mem::size_of::<SeccompNotifResp>(), 24);
        assert_eq!(std::mem::size_of::<SeccompData>(), 64);
        // _IOWR('!', 0, 80 bytes) = 0xC0502100
        assert_eq!(ioctl_recv(), 0xC050_2100);
        // _IOWR('!', 1, 24 bytes) = 0xC0182101
        assert_eq!(ioctl_send(), 0xC018_2101);
        // _IOW('!', 2, 8 bytes) = 0x40082102
        assert_eq!(ioctl_id_valid(), 0x4008_2102);
    }

    #[test]
    fn resolve_specs_accepts_ips() {
        let allow = resolve_allow_specs(&["10.0.0.5".into(), "127.0.0.1".into()]).unwrap();
        assert!(allow.allows_ip(&"10.0.0.5".parse().unwrap()));
    }
}
