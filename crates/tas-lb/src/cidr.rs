//! CIDR blocks for the PROXY-protocol trust list.
//!
//! The one place the LB decides "this sender may tell me who the client is", so the rules are
//! strict: an unparsable entry fails configuration (never silently dropped, which would shrink
//! the list unnoticed *or*, for a typo'd prefix, widen it), and an IPv4-mapped IPv6 peer address
//! is canonicalised to IPv4 before matching so `::ffff:10.0.0.1` cannot dodge or sneak into a
//! `10.0.0.0/8` entry on a dual-stack socket.

use std::net::IpAddr;

/// Why a CIDR string was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// Not `addr/prefix` or `addr`.
    Syntax,
    /// The prefix length exceeds the address family's width.
    PrefixTooLong,
}

impl core::fmt::Display for CidrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CidrError::Syntax => f.write_str("cidr: expected ADDR or ADDR/PREFIX"),
            CidrError::PrefixTooLong => {
                f.write_str("cidr: prefix longer than the address family allows")
            }
        }
    }
}

impl std::error::Error for CidrError {}

/// One block. The stored address is masked to the prefix, so equality means "same block".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse `ADDR/PREFIX`; a bare `ADDR` is a host route (/32 or /128).
    ///
    /// # Errors
    /// [`CidrError`] when the text is not an address with an in-range prefix.
    pub fn parse(s: &str) -> Result<Self, CidrError> {
        let (addr_s, prefix_s) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_s.trim().parse().map_err(|_| CidrError::Syntax)?;
        let addr = addr.to_canonical();
        let width: u8 = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_s {
            None => width,
            Some(p) => p.trim().parse::<u8>().map_err(|_| CidrError::Syntax)?,
        };
        if prefix > width {
            return Err(CidrError::PrefixTooLong);
        }
        Ok(Cidr {
            addr: mask(addr, prefix),
            prefix,
        })
    }

    /// Whether `ip` falls inside the block (families must match after canonicalisation).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        mask(ip, self.prefix) == self.addr
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4((bits & m).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6((bits & m).into())
        }
    }
}

/// An immutable list of blocks. Empty means "trust nobody" — the safe default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CidrSet(Vec<Cidr>);

impl CidrSet {
    /// Parse every entry, failing on the first bad one.
    ///
    /// # Errors
    /// The first [`CidrError`] encountered.
    pub fn parse_all<S: AsRef<str>>(entries: &[S]) -> Result<Self, CidrError> {
        entries
            .iter()
            .map(|s| Cidr::parse(s.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map(CidrSet)
    }

    /// Whether any block contains `ip`.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }

    /// No entries: nothing is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: deterministic assertions on fixtures"
    )]
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn v4_blocks_match_by_prefix() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains(ip("10.1.255.255")));
        assert!(!c.contains(ip("10.2.0.0")));
        assert!(!c.contains(ip("2001:db8::1")), "families never cross");
    }

    #[test]
    fn host_route_and_default_route() {
        assert!(Cidr::parse("192.0.2.7").unwrap().contains(ip("192.0.2.7")));
        assert!(!Cidr::parse("192.0.2.7").unwrap().contains(ip("192.0.2.8")));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains(ip("203.0.113.9")));
        assert!(Cidr::parse("::/0").unwrap().contains(ip("2001:db8::9")));
    }

    #[test]
    fn host_bits_in_the_text_are_masked_away() {
        assert_eq!(
            Cidr::parse("10.1.2.3/8").unwrap(),
            Cidr::parse("10.0.0.0/8").unwrap()
        );
    }

    #[test]
    fn v4_mapped_v6_peers_are_matched_as_v4() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("::ffff:10.9.9.9")));
        assert!(!c.contains(ip("::ffff:11.9.9.9")));
    }

    #[test]
    fn v6_prefixes() {
        let c = Cidr::parse("fd00:1::/32").unwrap();
        assert!(c.contains(ip("fd00:1:ffff::1")));
        assert!(!c.contains(ip("fd00:2::1")));
    }

    #[test]
    fn garbage_and_overlong_prefixes_are_refused() {
        assert_eq!(Cidr::parse("nope"), Err(CidrError::Syntax));
        assert_eq!(Cidr::parse("10.0.0.0/x"), Err(CidrError::Syntax));
        assert_eq!(Cidr::parse("10.0.0.0/33"), Err(CidrError::PrefixTooLong));
        assert_eq!(Cidr::parse("::/129"), Err(CidrError::PrefixTooLong));
        assert!(CidrSet::parse_all(&["10.0.0.0/8", "bad"]).is_err());
    }

    #[test]
    fn an_empty_set_trusts_nobody() {
        let s = CidrSet::default();
        assert!(s.is_empty());
        assert!(!s.contains(ip("127.0.0.1")));
    }
}
