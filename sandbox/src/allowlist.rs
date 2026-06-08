//! Pure egress-policy logic: parse a raw `sockaddr` and decide whether a
//! connection is allowed. No I/O, no `unsafe` — fully unit-testable. The
//! seccomp supervisor calls into this for every intercepted `connect()`.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The set of destinations an install is permitted to reach. Loopback is always
/// allowed (the gateway/registry proxy is reached over loopback or an explicit
/// allowlisted host); everything else is blocked and captured.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    hosts: HashSet<IpAddr>,
}

impl Allowlist {
    pub fn new(hosts: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            hosts: hosts.into_iter().collect(),
        }
    }

    /// Parse allow specs (bare IPs). Hostnames are resolved by the caller before
    /// constructing the allowlist, since `connect()` only ever sees IPs.
    /// (Primary construction at runtime is via `seccomp::resolve_allow_specs`.)
    #[allow(dead_code)]
    pub fn from_ip_strings<'a>(specs: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut hosts = HashSet::new();
        for spec in specs {
            let spec = spec.trim();
            if spec.is_empty() {
                continue;
            }
            let ip: IpAddr = spec
                .parse()
                .map_err(|_| format!("invalid allowlist IP: {spec}"))?;
            hosts.insert(ip);
        }
        Ok(Self { hosts })
    }

    pub fn allows_ip(&self, ip: &IpAddr) -> bool {
        ip.is_loopback() || self.hosts.contains(ip)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

/// Decide on a parsed destination. Non-IP families (AF_UNIX, AF_NETLINK, …) are
/// allowed — egress control only governs IP networking.
pub fn decide(allow: &Allowlist, dest: Option<SocketAddr>) -> Decision {
    match dest {
        Some(addr) if allow.allows_ip(&addr.ip()) => Decision::Allow,
        Some(_) => Decision::Block,
        None => Decision::Allow,
    }
}

/// AF_INET / AF_INET6 family numbers (Linux ABI).
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Parse a raw `sockaddr` (as copied from the tracee) into a `SocketAddr`.
/// Returns None for non-IP families or truncated buffers.
pub fn parse_sockaddr(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 2 {
        return None;
    }
    // sa_family is a u16 in native byte order.
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family {
        AF_INET => {
            // struct sockaddr_in: family(2) port(2, BE) addr(4)
            if buf.len() < 8 {
                return None;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let octets = [buf[4], buf[5], buf[6], buf[7]];
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        AF_INET6 => {
            // struct sockaddr_in6: family(2) port(2, BE) flowinfo(4) addr(16) scope(4)
            if buf.len() < 24 {
                return None;
            }
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sockaddr_in(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&AF_INET.to_ne_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v.extend_from_slice(&ip);
        v
    }

    #[test]
    fn parses_ipv4_sockaddr() {
        let buf = sockaddr_in([93, 184, 216, 34], 443);
        let addr = parse_sockaddr(&buf).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn parses_ipv6_sockaddr() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&AF_INET6.to_ne_bytes());
        buf.extend_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // flowinfo
        buf.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // scope
        let addr = parse_sockaddr(&buf).unwrap();
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn non_ip_family_is_none() {
        let buf = [1u8, 0, 0, 0]; // AF_UNIX
        assert!(parse_sockaddr(&buf).is_none());
    }

    #[test]
    fn truncated_buffer_is_none() {
        assert!(parse_sockaddr(&[2u8, 0, 1]).is_none());
    }

    #[test]
    fn loopback_always_allowed() {
        let allow = Allowlist::default();
        let lo = "127.0.0.1:443".parse().unwrap();
        assert_eq!(decide(&allow, Some(lo)), Decision::Allow);
    }

    #[test]
    fn allowlisted_host_allowed_others_blocked() {
        let allow = Allowlist::from_ip_strings(["10.0.0.5"]).unwrap();
        let gw = "10.0.0.5:443".parse().unwrap();
        let evil = "93.184.216.34:443".parse().unwrap();
        assert_eq!(decide(&allow, Some(gw)), Decision::Allow);
        assert_eq!(decide(&allow, Some(evil)), Decision::Block);
    }

    #[test]
    fn non_ip_destination_allowed() {
        let allow = Allowlist::default();
        assert_eq!(decide(&allow, None), Decision::Allow);
    }

    #[test]
    fn invalid_ip_spec_errors() {
        assert!(Allowlist::from_ip_strings(["not-an-ip"]).is_err());
    }
}
