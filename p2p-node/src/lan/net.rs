use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const PORT: u16 = 8308;
pub const PORT_LADDER: u16 = 10;

pub const VIRTUAL_PREFIXES: [&str; 14] = [
    "docker",
    "br-",
    "veth",
    "virbr",
    "vmnet",
    "vboxnet",
    "tun",
    "tap",
    "wg",
    "tailscale",
    "zt",
    "utun",
    "rmnet",
    "ccmni",
];
pub const WINDOWS_VIRTUAL_PREFIXES: [&str; 14] = [
    "vEthernet",
    "Hyper-V",
    "VirtualBox",
    "VMware",
    "ZeroTier",
    "TAP-",
    "OpenVPN",
    "WireGuard",
    "Wintun",
    "Tailscale",
    "NordLynx",
    "Hamachi",
    "Radmin VPN",
    "Npcap Loopback",
];
pub const MACOS_VIRTUAL_PREFIXES: [&str; 10] = [
    "utun", "feth", "bridge", "vmenet", "vmnet", "vboxnet", "tap", "tun", "zt", "ipsec",
];

const REFRESH: Duration = Duration::from_secs(30);
const REFRESH_ON_MISS: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub ip: IpAddr,
    pub prefixlen: u8,
    pub up: bool,
    pub p2p: bool,
}

#[derive(Default)]
struct Table {
    nets: Vec<(Ipv4Addr, u8)>,
    own: Vec<IpAddr>,
    read: Option<Instant>,
    failed: bool,
}

impl Table {
    fn of(ifaces: io::Result<Vec<Iface>>, now: Instant) -> Table {
        let Ok(ifaces) = ifaces else {
            return Table {
                read: Some(now),
                failed: true,
                ..Table::default()
            };
        };
        let mut table = Table {
            read: Some(now),
            ..Table::default()
        };
        for iface in ifaces {
            let ip = iface.ip.to_canonical();
            table.own.push(ip);
            if let IpAddr::V4(v4) = ip {
                let lan = iface.up
                    && !iface.p2p
                    && !v4.is_loopback()
                    && !is_virtual(&iface.name)
                    && (8..=32).contains(&iface.prefixlen);
                if lan {
                    table.nets.push((v4, iface.prefixlen));
                }
            }
        }
        table
    }

    fn own(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.own.contains(&ip)
    }

    fn neighbour(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(v4) = ip else {
            return false;
        };
        !self.failed
            && !self.own(ip)
            && (self.nets.iter()).any(|&(net, prefix)| same_subnet(net, v4, prefix))
    }

    fn accepts(&self, ip: IpAddr) -> bool {
        if self.own(ip) {
            return true;
        }
        let IpAddr::V4(v4) = ip else {
            return false;
        };
        is_private(ip)
            && (self.failed
                || (self.nets.iter()).any(|&(net, prefix)| same_subnet(net, v4, prefix)))
    }
}

pub struct OnLink {
    test_mode: bool,
    fixed: bool,
    table: Mutex<Table>,
}

impl OnLink {
    pub fn new(test_mode: bool) -> Self {
        let on_link = Self {
            test_mode,
            fixed: false,
            table: Mutex::new(Table::default()),
        };
        on_link.refresh();
        on_link
    }

    pub fn with_interfaces(test_mode: bool, ifaces: Vec<Iface>) -> Self {
        Self {
            test_mode,
            fixed: true,
            table: Mutex::new(Table::of(Ok(ifaces), Instant::now())),
        }
    }

    pub fn refresh(&self) {
        if self.fixed {
            return;
        }
        let table = Table::of(interfaces(), Instant::now());
        *self.table.lock().unwrap() = table;
    }

    pub fn fallback(&self) -> bool {
        self.table.lock().unwrap().failed
    }

    pub fn accepts(&self, ip: IpAddr) -> bool {
        self.check(ip.to_canonical(), Table::accepts)
    }

    pub fn neighbour(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        is_private(ip) && self.check(ip, Table::neighbour)
    }

    pub fn own(&self, ip: IpAddr) -> bool {
        self.check(ip.to_canonical(), Table::own)
    }

    pub fn test_mode(&self) -> bool {
        self.test_mode
    }

    fn check(&self, ip: IpAddr, test: fn(&Table, IpAddr) -> bool) -> bool {
        let now = Instant::now();
        let age = |table: &Table| table.read.map(|read| now.saturating_duration_since(read));
        let mut table = self.table.lock().unwrap();
        if !self.fixed && age(&table).is_none_or(|age| age >= REFRESH) {
            *table = Table::of(interfaces(), now);
        }
        if test(&table, ip) {
            return true;
        }
        if self.fixed || age(&table).is_some_and(|age| age < REFRESH_ON_MISS) {
            return false;
        }
        *table = Table::of(interfaces(), now);
        test(&table, ip)
    }
}

fn interfaces() -> io::Result<Vec<Iface>> {
    Ok(if_addrs::get_if_addrs()?
        .into_iter()
        .map(|iface| {
            let prefixlen = match &iface.addr {
                if_addrs::IfAddr::V4(v4) => v4.prefixlen,
                if_addrs::IfAddr::V6(v6) => v6.prefixlen,
            };
            Iface {
                ip: iface.ip(),
                prefixlen,
                up: iface.is_oper_up(),
                p2p: iface.is_p2p(),
                name: iface.name,
            }
        })
        .collect())
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(a) & mask == u32::from(b) & mask
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(_) => false,
    }
}

pub fn is_virtual(name: &str) -> bool {
    let prefixes: &[&str] = if cfg!(windows) {
        &WINDOWS_VIRTUAL_PREFIXES
    } else if cfg!(target_os = "macos") {
        &MACOS_VIRTUAL_PREFIXES
    } else {
        &VIRTUAL_PREFIXES
    };
    starts_with_any(prefixes, name)
}

fn starts_with_any(prefixes: &[&str], name: &str) -> bool {
    (prefixes.iter())
        .any(|prefix| (name.get(..prefix.len())).is_some_and(|s| s.eq_ignore_ascii_case(prefix)))
}

pub fn order_addrs(
    on_link: &OnLink,
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    let mut ranked: Vec<(u8, SocketAddr)> = Vec::new();
    for addr in addrs {
        let ip = addr.ip().to_canonical();
        let IpAddr::V4(v4) = ip else {
            continue;
        };
        if v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() || addr.port() == 0 {
            continue;
        }
        let rank = if v4.is_loopback() {
            if !on_link.test_mode() {
                continue;
            }
            2
        } else if !on_link.accepts(ip) {
            continue;
        } else if on_link.own(ip) {
            1
        } else {
            0
        };
        let addr = SocketAddr::new(ip, addr.port());
        if !ranked.iter().any(|(_, seen)| *seen == addr) {
            ranked.push((rank, addr));
        }
    }
    ranked.sort_by_key(|(rank, _)| *rank);
    ranked.into_iter().map(|(_, addr)| addr).collect()
}

pub fn bind_ladder(ip: Ipv4Addr, port: u16, fixed: bool) -> io::Result<TcpListener> {
    if fixed || port == 0 {
        return TcpListener::bind((ip, port));
    }
    for port in port..port.saturating_add(PORT_LADDER) {
        match TcpListener::bind((ip, port)) {
            Ok(listener) => return Ok(listener),
            Err(e) if ladder_goes_on(e.kind()) => continue,
            Err(e) => return Err(e),
        }
    }
    TcpListener::bind((ip, 0))
}

fn ladder_goes_on(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::AddrInUse
            // Windows answers WSAEACCES for ports reserved by Hyper-V and WSL.
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::AddrNotAvailable
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, prefixlen: u8) -> Iface {
        Iface {
            name: name.into(),
            ip: ip.parse().unwrap(),
            prefixlen,
            up: true,
            p2p: false,
        }
    }

    fn table(test_mode: bool) -> OnLink {
        OnLink::with_interfaces(
            test_mode,
            vec![
                iface("lo", "127.0.0.1", 8),
                iface("wlp0s20f3", "192.168.1.10", 24),
                iface("eth1", "203.0.113.5", 24),
                Iface {
                    p2p: true,
                    ..iface("ppp0", "10.64.0.2", 8)
                },
                iface("docker0", "172.17.0.1", 16),
                Iface {
                    up: false,
                    ..iface("eth2", "10.9.0.1", 16)
                },
                iface("wlp0s20f3", "fe80::1", 64),
            ],
        )
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn private_and_virtual() {
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.3.4",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "172.32.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
        assert!(is_private("::ffff:192.168.1.1".parse().unwrap()));
        let linux = |name| starts_with_any(&VIRTUAL_PREFIXES, name);
        for name in [
            "docker0",
            "br-1a2b",
            "veth12",
            "virbr0",
            "tun0",
            "wg0",
            "tailscale0",
            "utun3",
            "zt5u4y6abc",
            "rmnet_data0",
        ] {
            assert!(linux(name), "{name}");
        }
        for name in ["eth0", "enp8s0", "wlp0s20f3", "wlan0", "lo", "br0"] {
            assert!(!linux(name), "{name}");
        }
        let windows = |name| starts_with_any(&WINDOWS_VIRTUAL_PREFIXES, name);
        for name in [
            "ZeroTier One [8056c2e21c000001]",
            "vEthernet (WSL)",
            "VEthernet (Default Switch)",
            "VirtualBox Host-Only Network",
            "VMware Network Adapter VMnet8",
            "OpenVPN TAP-Windows6",
            "OpenVPN Wintun",
            "Tailscale",
        ] {
            assert!(windows(name), "{name}");
        }
        for name in ["Ethernet", "Wi-Fi", "Ethernet 2", "Беспроводная сеть"] {
            assert!(!windows(name), "{name}");
        }
        let macos = |name| starts_with_any(&MACOS_VIRTUAL_PREFIXES, name);
        for name in ["feth3209", "bridge100", "vmenet0", "utun4"] {
            assert!(macos(name), "{name}");
        }
        for name in ["en0", "en7", "lo0", "awdl0"] {
            assert!(!macos(name), "{name}");
        }
        assert_eq!(
            is_virtual("Docker0"),
            cfg!(not(any(windows, target_os = "macos")))
        );
    }

    #[test]
    fn on_link() {
        let on_link = table(false);
        assert!(on_link.accepts(ip("192.168.1.77")));
        assert!(on_link.accepts(ip("::ffff:192.168.1.1")));
        assert!(!on_link.accepts(ip("192.168.2.1")));
        assert!(!on_link.accepts(ip("203.0.113.9")));
        assert!(!on_link.accepts(ip("100.64.0.1")));
        assert!(!on_link.accepts(ip("8.8.8.8")));
        assert!(!on_link.accepts(ip("10.64.0.9")));
        assert!(!on_link.accepts(ip("172.17.0.2")));
        assert!(!on_link.accepts(ip("10.9.0.2")));
        assert!(!on_link.accepts(ip("fe80::2")));
        assert!(on_link.accepts(ip("127.0.0.1")));
        assert!(on_link.accepts(ip("::1")));
        assert!(on_link.accepts(ip("203.0.113.5")));
        assert!(on_link.accepts(ip("172.17.0.1")));
        assert!(on_link.own(ip("192.168.1.10")));
        assert!(on_link.own(ip("127.0.0.1")));
        assert!(!on_link.own(ip("192.168.1.77")));
        assert!(!on_link.fallback());

        let failed = OnLink {
            test_mode: false,
            fixed: true,
            table: Mutex::new(Table::of(Err(io::Error::other("netlink")), Instant::now())),
        };
        assert!(failed.fallback());
        assert!(failed.accepts(ip("10.1.2.3")));
        assert!(!failed.accepts(ip("100.64.0.1")));
        assert!(!failed.neighbour(ip("10.1.2.3")), "fails closed");
    }

    #[test]
    fn neighbours() {
        let on_link = table(false);
        assert!(on_link.neighbour(ip("192.168.1.77")));
        assert!(on_link.neighbour(ip("::ffff:192.168.1.77")));
        for other in [
            "127.0.0.1",
            "::1",
            "192.168.1.10",
            "203.0.113.5",
            "172.17.0.1",
            "192.168.2.1",
            "203.0.113.9",
            "100.64.0.1",
            "10.64.0.9",
            "172.17.0.2",
            "fe80::2",
            "fd12::20",
            "64:ff9b::c0a8:14d",
        ] {
            assert!(!on_link.neighbour(ip(other)), "{other}");
        }
    }

    #[test]
    fn address_order() {
        let addrs = |list: &[&str]| -> Vec<SocketAddr> {
            list.iter().map(|addr| addr.parse().unwrap()).collect()
        };
        let input = addrs(&[
            "127.0.0.1:47800",
            "192.168.1.10:47800",
            "8.8.8.8:47800",
            "[fe80::2]:47800",
            "192.168.1.30:47800",
            "192.168.1.30:47800",
            "192.168.1.31:0",
            "10.64.0.9:47800",
        ]);
        assert_eq!(
            order_addrs(&table(false), input.clone()),
            addrs(&["192.168.1.30:47800", "192.168.1.10:47800"])
        );
        assert_eq!(
            order_addrs(&table(true), input),
            addrs(&[
                "192.168.1.30:47800",
                "192.168.1.10:47800",
                "127.0.0.1:47800"
            ])
        );
    }

    #[test]
    fn ladder() {
        let first = bind_ladder(Ipv4Addr::LOCALHOST, 0, false).unwrap();
        let port = first.local_addr().unwrap().port();
        let next = bind_ladder(Ipv4Addr::LOCALHOST, port, false).unwrap();
        assert_ne!(next.local_addr().unwrap().port(), port);
        assert!(bind_ladder(Ipv4Addr::LOCALHOST, port, true).is_err());
        assert!(ladder_goes_on(io::ErrorKind::PermissionDenied));
        assert!(!ladder_goes_on(io::ErrorKind::InvalidInput));
    }

    #[test]
    fn ladder_ends_in_any_free_port() {
        assert_eq!(PORT..PORT + PORT_LADDER, 8308..8318);
        let held: Vec<TcpListener> = (0..20)
            .find_map(|_| {
                let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
                let base = first.local_addr().ok()?.port();
                let mut held = vec![first];
                for port in base.checked_add(1)?..base.checked_add(PORT_LADDER)? {
                    held.push(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).ok()?);
                }
                Some(held)
            })
            .unwrap();
        let base = held[0].local_addr().unwrap().port();
        let any = bind_ladder(Ipv4Addr::LOCALHOST, base, false).unwrap();
        let port = any.local_addr().unwrap().port();
        assert!(!(base..base + PORT_LADDER).contains(&port), "{port}");
    }
}
