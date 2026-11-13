use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use mdns_sd::{IfKind, IfPredicate, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use sha2::{Digest, Sha256};

use crate::lan::{id, net};

const SERVICE: &str = "_nodeinnet._tcp.local.";
const TXT_V: &str = "v";
const TXT_ID: &str = "id";
const TXT_NAME: &str = "n";
const TXT_OS: &str = "os";
const TXT_KIND: &str = "k";
const TXT_VERSION: &str = "1";
const MAX_IDS: usize = 64;
const MAX_ADDRS: usize = 4;
const MAX_ANNOUNCERS: usize = 4;
const MAX_BAD: usize = 256;
const BAD_FOR: Duration = Duration::from_secs(600);
const RENAME_OVERLAP: Duration = Duration::from_secs(3);
const UNREGISTER_WAIT: Duration = Duration::from_millis(500);
const MANUAL: &str = "manual";

fn configure(daemon: &ServiceDaemon, test_mode: bool) -> Result<(), mdns_sd::Error> {
    daemon.disable_interface(vec![IfKind::IPv6, IfKind::LoopbackV6])?;
    if test_mode {
        daemon.disable_interface(IfKind::Predicate(IfPredicate::new(
            |interface: &if_addrs::Interface| !interface.is_loopback(),
        )))?;
    } else {
        daemon.disable_interface(IfKind::LoopbackV4)?;
        daemon.disable_interface(IfKind::Predicate(IfPredicate::new(
            |interface: &if_addrs::Interface| {
                !interface.is_loopback()
                    && (net::is_virtual(&interface.name) || !net::is_private(interface.ip()))
            },
        )))?;
    }
    #[cfg(target_os = "android")]
    daemon.set_ip_check_interval(5)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Advert {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) os: String,
    pub(crate) kind: String,
    pub(crate) port: u16,
}

fn host_name(id: &str, instance: &str) -> String {
    let digest = Sha256::digest(instance.as_bytes());
    format!(
        "nin-{}-{:02x}{:02x}.local.",
        id::id8(id),
        digest[0],
        digest[1]
    )
}

fn service_info(advert: &Advert) -> Result<ServiceInfo, mdns_sd::Error> {
    let name = id::sanitize_name(&advert.name);
    let shown = if name.is_empty() {
        "Node In Net"
    } else {
        &name
    };
    let instance = id::instance_name(shown, &advert.id);
    let host = host_name(&advert.id, &instance);
    let txt = [
        (TXT_V, TXT_VERSION.to_string()),
        (TXT_ID, advert.id.clone()),
        (TXT_NAME, name.clone()),
        (TXT_OS, advert.os.clone()),
        (TXT_KIND, advert.kind.clone()),
    ];
    let info = ServiceInfo::new(SERVICE, &instance, &host, (), advert.port, &txt[..])?;
    Ok(info.enable_addr_auto())
}

fn retires(old: &str, new: &str) -> bool {
    old.to_lowercase() != new.to_lowercase()
}

pub(crate) struct Mdns {
    daemon: ServiceDaemon,
    registered: Option<(String, Advert)>,
    retiring: Vec<(String, Instant)>,
    browsing: bool,
}

impl Mdns {
    pub(crate) fn new(test_mode: bool) -> Result<Mdns, mdns_sd::Error> {
        let mdns = Mdns {
            daemon: ServiceDaemon::new()?,
            registered: None,
            retiring: Vec::new(),
            browsing: false,
        };
        configure(&mdns.daemon, test_mode)?;
        Ok(mdns)
    }

    pub(crate) fn advertise(
        &mut self,
        advert: Option<Advert>,
        now: Instant,
    ) -> Result<(), mdns_sd::Error> {
        let Some(advert) = advert else {
            let names = (self.registered.take().map(|(fullname, _)| fullname))
                .into_iter()
                .chain(self.retiring.drain(..).map(|(fullname, _)| fullname));
            for fullname in names {
                let _ = self.daemon.unregister(&fullname);
            }
            return Ok(());
        };
        if self.registered.as_ref().map(|(_, old)| old) == Some(&advert) {
            return Ok(());
        }
        let info = service_info(&advert)?;
        let fullname = info.get_fullname().to_string();
        self.daemon.register(info)?;
        self.retiring.retain(|(old, _)| retires(old, &fullname));
        if let Some((old, _)) = self.registered.replace((fullname.clone(), advert)) {
            if retires(&old, &fullname) {
                self.retiring.push((old, now + RENAME_OVERLAP));
            }
        }
        Ok(())
    }

    pub(crate) fn retire_due(&mut self, now: Instant) {
        let daemon = &self.daemon;
        self.retiring.retain(|(fullname, at)| {
            if *at > now {
                return true;
            }
            let _ = daemon.unregister(fullname);
            false
        });
    }

    pub(crate) fn browse(
        &mut self,
    ) -> Result<Option<mdns_sd::Receiver<ServiceEvent>>, mdns_sd::Error> {
        if self.browsing {
            return Ok(None);
        }
        let events = self.daemon.browse(SERVICE)?;
        self.browsing = true;
        Ok(Some(events))
    }

    pub(crate) fn stop_browse(&mut self) {
        if std::mem::take(&mut self.browsing) {
            let _ = self.daemon.stop_browse(SERVICE);
        }
    }

    pub(crate) async fn stop(mut self, deadline: tokio::time::Instant) {
        let names: Vec<String> = (self.registered.take().map(|(fullname, _)| fullname))
            .into_iter()
            .chain(self.retiring.drain(..).map(|(fullname, _)| fullname))
            .collect();
        let goodbyes: Vec<_> = (names.iter())
            .filter_map(|fullname| self.daemon.unregister(fullname).ok())
            .collect();
        let wait = (tokio::time::Instant::now() + UNREGISTER_WAIT).min(deadline);
        for goodbye in goodbyes {
            let _ = tokio::time::timeout_at(wait, goodbye.recv_async()).await;
        }
        self.stop_browse();
        if let Ok(status) = self.daemon.shutdown() {
            let _ = tokio::time::timeout_at(deadline, status.recv_async()).await;
        }
    }
}

impl Drop for Mdns {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}

pub(crate) fn keep(on_link: &net::OnLink, addr: SocketAddr) -> bool {
    let IpAddr::V4(v4) = addr.ip() else {
        return false;
    };
    addr.port() != 0
        && !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast())
        && (on_link.test_mode() || !v4.is_loopback())
        && on_link.accepts(addr.ip())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Found {
    pub(crate) fullname: String,
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) os: String,
    pub(crate) kind: String,
    pub(crate) addrs: Vec<SocketAddr>,
}

impl Found {
    pub(crate) fn parse(service: &ResolvedService) -> Option<Found> {
        let txt = |key| service.get_property_val_str(key).unwrap_or_default();
        let id = txt(TXT_ID);
        if txt(TXT_V).trim() != TXT_VERSION || !id::is_id(id) {
            return None;
        }
        let mut addrs: Vec<SocketAddr> = (service.addresses.iter())
            .map(|ip| ip.to_ip_addr())
            .filter(IpAddr::is_ipv4)
            .map(|ip| SocketAddr::new(ip, service.port))
            .collect();
        addrs.sort();
        Some(Found {
            fullname: service.fullname.clone(),
            id: id.to_string(),
            name: id::sanitize_name(txt(TXT_NAME)),
            os: id::sanitize_name(txt(TXT_OS)),
            kind: id::sanitize_name(txt(TXT_KIND)),
            addrs,
        })
    }
}

struct Announcer {
    fullname: String,
    addrs: Vec<SocketAddr>,
}

pub(crate) struct Entry {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) os: String,
    pub(crate) kind: String,
    pub(crate) seen: Instant,
    announcers: Vec<Announcer>,
}

impl Entry {
    fn new(id: &str, now: Instant) -> Entry {
        Entry {
            id: id.to_string(),
            name: String::new(),
            os: String::new(),
            kind: String::new(),
            seen: now,
            announcers: Vec::new(),
        }
    }

    pub(crate) fn addrs(&self) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();
        for addr in self.announcers.iter().flat_map(|a| a.addrs.iter()) {
            if !addrs.contains(addr) {
                addrs.push(*addr);
            }
        }
        addrs
    }

    fn reachable(&self) -> bool {
        self.announcers.iter().any(|a| !a.addrs.is_empty())
    }

    fn cap(&mut self) {
        self.announcers.truncate(MAX_ANNOUNCERS);
        let mut kept: Vec<SocketAddr> = Vec::new();
        for announcer in &mut self.announcers {
            announcer.addrs.retain(|addr| {
                if kept.contains(addr) {
                    return true;
                }
                if kept.len() < MAX_ADDRS {
                    kept.push(*addr);
                    return true;
                }
                false
            });
        }
    }

    fn forget(&mut self, addr: SocketAddr) {
        for announcer in &mut self.announcers {
            announcer.addrs.retain(|a| *a != addr);
        }
    }
}

#[derive(Default)]
pub(crate) struct Seen {
    entries: Vec<Entry>,
    bad: Vec<(String, SocketAddr, Instant)>,
}

impl Seen {
    pub(crate) fn found(
        &mut self,
        found: Found,
        keep: &dyn Fn(SocketAddr) -> bool,
        now: Instant,
    ) -> bool {
        let moved = self.forget_fullname(&found.fullname, Some(&found.id));
        let mut addrs = Vec::new();
        for addr in found.addrs {
            if keep(addr) && !self.is_bad(&found.id, addr, now) && !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
        let index = match self.index(&found.id) {
            Some(index) => index,
            None if addrs.is_empty() => return moved,
            None => self.add(&found.id, now),
        };
        let entry = &mut self.entries[index];
        entry.seen = now;
        entry.name = found.name;
        entry.os = found.os;
        entry.kind = found.kind;
        entry.announcers.retain(|a| a.fullname != found.fullname);
        entry.announcers.insert(
            0,
            Announcer {
                fullname: found.fullname,
                addrs,
            },
        );
        entry.cap();
        if !entry.reachable() {
            self.entries.remove(index);
        }
        true
    }

    pub(crate) fn removed(&mut self, fullname: &str) -> bool {
        self.forget_fullname(fullname, None)
    }

    pub(crate) fn bad(&mut self, id: &str, addr: SocketAddr, now: Instant) {
        self.bad
            .retain(|(bad_id, bad, until)| *until > now && !(bad_id == id && *bad == addr));
        if self.bad.len() >= MAX_BAD {
            self.bad.remove(0);
        }
        self.bad.push((id.to_string(), addr, now + BAD_FOR));
        if let Some(index) = self.index(id) {
            self.entries[index].forget(addr);
            if !self.entries[index].reachable() {
                self.entries.remove(index);
            }
        }
    }

    pub(crate) fn is_bad(&self, id: &str, addr: SocketAddr, now: Instant) -> bool {
        (self.bad.iter()).any(|(bad_id, bad, until)| bad_id == id && *bad == addr && *until > now)
    }

    pub(crate) fn addrs(&self, id: &str) -> Vec<SocketAddr> {
        self.get(id).map(Entry::addrs).unwrap_or_default()
    }

    pub(crate) fn has(&self, id: &str) -> bool {
        self.index(id).is_some()
    }

    pub(crate) fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub(crate) fn devices(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    pub(crate) fn inject(&mut self, id: &str, addr: SocketAddr, now: Instant) {
        let index = match self.index(id) {
            Some(index) => index,
            None => self.add(id, now),
        };
        let entry = &mut self.entries[index];
        entry.seen = now;
        if entry.name.is_empty() {
            entry.name = id::id8(id).to_string();
        }
        let mut addrs = vec![addr];
        if let Some(i) = (entry.announcers.iter()).position(|a| a.fullname == MANUAL) {
            let old = entry.announcers.remove(i);
            addrs.extend(old.addrs.into_iter().filter(|a| *a != addr));
        }
        entry.announcers.insert(
            0,
            Announcer {
                fullname: MANUAL.to_string(),
                addrs,
            },
        );
        entry.cap();
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    fn index(&self, id: &str) -> Option<usize> {
        self.entries.iter().position(|e| e.id == id)
    }

    fn add(&mut self, id: &str, now: Instant) -> usize {
        if self.entries.len() >= MAX_IDS {
            let oldest = (self.entries.iter().enumerate())
                .min_by_key(|(_, e)| e.seen)
                .map(|(index, _)| index);
            if let Some(oldest) = oldest {
                self.entries.remove(oldest);
            }
        }
        self.entries.push(Entry::new(id, now));
        self.entries.len() - 1
    }

    fn forget_fullname(&mut self, fullname: &str, except: Option<&str>) -> bool {
        let mut changed = false;
        self.entries.retain_mut(|entry| {
            if except == Some(entry.id.as_str()) {
                return true;
            }
            let before = entry.announcers.len();
            entry.announcers.retain(|a| a.fullname != fullname);
            if entry.announcers.len() == before {
                return true;
            }
            changed = true;
            entry.reachable()
        });
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaa000000000000000000000000";
    const B: &str = "bbbbbbbb000000000000000000000000";
    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn found(fullname: &str, id: &str, name: &str, addrs: &[&str]) -> Found {
        Found {
            fullname: fullname.into(),
            id: id.into(),
            name: name.into(),
            os: "linux".into(),
            kind: "desktop".into(),
            addrs: addrs.iter().map(|a| addr(a)).collect(),
        }
    }

    fn keep(addr: SocketAddr) -> bool {
        match addr.ip() {
            IpAddr::V4(v4) => {
                addr.port() != 0 && (v4.is_loopback() || v4.octets()[..3] == [192, 168, 1])
            }
            IpAddr::V6(_) => false,
        }
    }

    fn advert(name: &str) -> Advert {
        Advert {
            id: ID.into(),
            name: name.into(),
            os: "linux".into(),
            kind: "desktop".into(),
            port: 8308,
        }
    }

    #[test]
    fn the_advert() {
        let info = service_info(&advert("Living room PC")).unwrap();
        assert_eq!(
            info.get_fullname(),
            "Living room PC [01234567]._nodeinnet._tcp.local."
        );
        let host = info.get_hostname();
        let hex = host
            .strip_prefix("nin-01234567-")
            .and_then(|rest| rest.strip_suffix(".local."))
            .unwrap_or_else(|| panic!("{host}"));
        assert!(
            hex.len() == 4 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{host}"
        );
        assert_eq!(info.get_property_val_str("v"), Some("1"));
        assert_eq!(info.get_property_val_str("id"), Some(ID));
        assert_eq!(info.get_property_val_str("n"), Some("Living room PC"));
        assert_eq!(info.get_property_val_str("os"), Some("linux"));
        assert_eq!(info.get_property_val_str("k"), Some("desktop"));
        assert_eq!(info.get_properties().len(), 5);
        assert_eq!(info.get_port(), 8308);

        let renamed = service_info(&advert("Kitchen")).unwrap();
        assert_ne!(renamed.get_hostname(), info.get_hostname());
        for length in [60, 70] {
            let long = service_info(&advert(&"n".repeat(length))).unwrap();
            assert_eq!(
                long.get_fullname(),
                format!("{} [01234567]._nodeinnet._tcp.local.", "n".repeat(40))
            );
            let name = long.get_property_val_str("n").unwrap();
            assert_eq!(name.len(), length.min(63));
        }
        let unnamed = service_info(&advert("\u{202e}")).unwrap();
        assert!(unnamed
            .get_fullname()
            .starts_with("Node In Net [01234567]."));
    }

    #[test]
    fn found_lists_v1_with_a_valid_id_only() {
        let txt = [
            ("v", " 1 "),
            ("id", A),
            ("n", "TV\u{202e}\n room"),
            ("os", "android"),
            ("k", "tv"),
        ];
        let info = ServiceInfo::new(
            SERVICE,
            "TV [aaaaaaaa]",
            "nin-aaaaaaaa-0000.local.",
            "192.168.1.7,fe80::1",
            8308,
            &txt[..],
        )
        .unwrap();
        let found = Found::parse(&info.as_resolved_service()).unwrap();
        assert_eq!(found.fullname, "TV [aaaaaaaa]._nodeinnet._tcp.local.");
        assert_eq!(found.id, A);
        assert_eq!(found.name, "TV  room");
        assert_eq!((found.os.as_str(), found.kind.as_str()), ("android", "tv"));
        assert_eq!(found.addrs, [addr("192.168.1.7:8308")]);

        let upper = A.to_uppercase();
        for (v, id) in [
            ("2", A),
            ("", A),
            ("1", "AAAA"),
            ("1", upper.as_str()),
            ("1", ""),
        ] {
            let txt = [("v", v), ("id", id)];
            let info =
                ServiceInfo::new(SERVICE, "x", "x.local.", "192.168.1.7", 1, &txt[..]).unwrap();
            assert!(
                Found::parse(&info.as_resolved_service()).is_none(),
                "{v} {id}"
            );
        }
    }

    #[test]
    fn seen_keeps_64_ids_of_4_addresses() {
        let now = Instant::now();
        let mut seen = Seen::default();
        let name = "X [aaaaaaaa]._nodeinnet._tcp.local.";
        let addrs = [
            "192.168.1.1:1",
            "192.168.1.2:1",
            "192.168.1.3:1",
            "192.168.1.4:1",
            "192.168.1.5:1",
            "127.0.0.1:1",
        ];
        assert!(seen.found(found(name, A, "X", &addrs), &keep, now));
        assert_eq!(seen.addrs(A).len(), MAX_ADDRS);
        for n in 0..10 {
            let other = format!("X{n} [aaaaaaaa]._nodeinnet._tcp.local.");
            seen.found(found(&other, A, "X", &["192.168.1.9:1"]), &keep, now);
        }
        assert_eq!(seen.get(A).unwrap().announcers.len(), MAX_ANNOUNCERS);
        assert_eq!(seen.addrs(A), [addr("192.168.1.9:1")]);

        let mut seen = Seen::default();
        for n in 0..=MAX_IDS {
            let id = format!("{n:032x}");
            let at = now + Duration::from_millis(n as u64);
            seen.found(
                found(&n.to_string(), &id, "X", &["192.168.1.1:1"]),
                &keep,
                at,
            );
        }
        assert_eq!(seen.devices().count(), MAX_IDS);
        assert!(!seen.has(&format!("{:032x}", 0)));
        assert!(seen.has(&format!("{MAX_IDS:032x}")));
    }

    #[test]
    fn a_goodbye_drops_only_its_announcer() {
        let now = Instant::now();
        let mut seen = Seen::default();
        let old = "TV [aaaaaaaa]._nodeinnet._tcp.local.";
        let new = "Kitchen TV [aaaaaaaa]._nodeinnet._tcp.local.";
        seen.found(found(old, A, "TV", &["192.168.1.7:8308"]), &keep, now);
        seen.found(
            found(new, A, "Kitchen TV", &["192.168.1.8:8308"]),
            &keep,
            now,
        );
        assert_eq!(seen.get(A).unwrap().name, "Kitchen TV");
        assert_eq!(
            seen.addrs(A),
            [addr("192.168.1.8:8308"), addr("192.168.1.7:8308")]
        );
        assert!(seen.removed(old));
        assert_eq!(seen.addrs(A), [addr("192.168.1.8:8308")]);
        assert!(seen.removed(new));
        assert!(!seen.has(A));
        assert!(!seen.removed(new));
    }

    #[test]
    fn an_instance_that_claims_another_id_moves() {
        let now = Instant::now();
        let mut seen = Seen::default();
        let name = "Box [aaaaaaaa]._nodeinnet._tcp.local.";
        seen.found(found(name, A, "Box", &["192.168.1.7:8308"]), &keep, now);
        assert!(seen.found(found(name, B, "Box", &["192.168.1.7:8308"]), &keep, now));
        assert!(!seen.has(A));
        assert_eq!(seen.addrs(B), [addr("192.168.1.7:8308")]);

        seen.found(found("a2", A, "A", &["192.168.1.9:8308"]), &keep, now);
        seen.found(found("a3", A, "A", &["192.168.1.10:8308"]), &keep, now);
        seen.found(found("a2", B, "B", &["192.168.1.11:8308"]), &keep, now);
        assert_eq!(seen.addrs(A), [addr("192.168.1.10:8308")]);
        assert_eq!(
            seen.addrs(B),
            [addr("192.168.1.11:8308"), addr("192.168.1.7:8308")]
        );
    }

    #[test]
    fn bad_addresses_are_skipped_for_ten_minutes() {
        let now = Instant::now();
        let mut seen = Seen::default();
        let name = "B [bbbbbbbb]._nodeinnet._tcp.local.";
        let (first, second) = (addr("192.168.1.7:8308"), addr("192.168.1.8:8308"));
        seen.found(
            found(name, B, "B", &["192.168.1.7:8308", "192.168.1.8:8308"]),
            &keep,
            now,
        );
        seen.bad(B, first, now);
        assert!(seen.is_bad(B, first, now));
        assert!(!seen.is_bad(A, first, now) && !seen.is_bad(B, second, now));
        assert_eq!(seen.addrs(B), [second]);
        seen.found(found(name, B, "B", &["192.168.1.7:8308"]), &keep, now);
        assert!(!seen.has(B));

        let later = now + BAD_FOR;
        assert!(!seen.is_bad(B, first, later));
        assert!(seen.found(found(name, B, "B", &["192.168.1.7:8308"]), &keep, later));
        assert_eq!(seen.addrs(B), [first]);

        seen.bad(A, addr("192.168.1.9:8308"), later);
        let only_bad = found("A [aaaaaaaa]", A, "A", &["192.168.1.9:8308"]);
        assert!(!seen.found(only_bad, &keep, later));
        assert!(!seen.has(A));
        for n in 0..300u16 {
            let [high, low] = n.to_be_bytes();
            seen.bad(A, SocketAddr::from(([10, 0, high, low], 1)), later);
        }
        assert_eq!(seen.bad.len(), MAX_BAD);
        assert!(seen.is_bad(A, SocketAddr::from(([10, 0, 1, 43], 1)), later));
        assert!(!seen.is_bad(A, SocketAddr::from(([10, 0, 0, 0], 1)), later));
    }

    #[test]
    fn addresses_the_filter_refuses_are_not_kept() {
        let now = Instant::now();
        let mut seen = Seen::default();
        let refused = found("X", A, "X", &["10.0.0.1:1", "192.168.1.1:0", "8.8.8.8:1"]);
        assert!(!seen.found(refused, &keep, now));
        assert!(!seen.has(A));

        let lan = net::Iface {
            name: "wlan0".into(),
            ip: "192.168.1.10".parse().unwrap(),
            prefixlen: 24,
            up: true,
            p2p: false,
        };
        let on_link = net::OnLink::with_interfaces(false, vec![lan.clone()]);
        assert!(super::keep(&on_link, addr("192.168.1.20:8308")));
        for other in [
            "192.168.1.20:0",
            "127.0.0.1:8308",
            "10.1.1.1:8308",
            "224.0.0.251:8308",
            "255.255.255.255:8308",
            "0.0.0.0:8308",
            "[fe80::1]:8308",
        ] {
            assert!(!super::keep(&on_link, addr(other)), "{other}");
        }
        let testing = net::OnLink::with_interfaces(true, vec![lan]);
        assert!(super::keep(&testing, addr("127.0.0.1:8308")));
    }

    #[test]
    fn clear_keeps_bad() {
        let now = Instant::now();
        let mut seen = Seen::default();
        seen.found(found("X", A, "X", &["192.168.1.1:1"]), &keep, now);
        seen.bad(B, addr("192.168.1.2:1"), now);
        seen.clear();
        assert_eq!(seen.devices().count(), 0);
        assert!(seen.is_bad(B, addr("192.168.1.2:1"), now));
    }

    #[test]
    fn injected_addresses_sit_beside_announced_ones() {
        let now = Instant::now();
        let mut seen = Seen::default();
        seen.inject(A, addr("127.0.0.1:9"), now);
        seen.inject(B, addr("127.0.0.1:10"), now);
        seen.inject(A, addr("127.0.0.1:11"), now);
        assert_eq!(seen.get(A).unwrap().name, "aaaaaaaa");
        assert_eq!(seen.addrs(A), [addr("127.0.0.1:11"), addr("127.0.0.1:9")]);
        assert!(seen.has(B));
        seen.found(found("TV", A, "TV", &["192.168.1.5:1"]), &keep, now);
        assert_eq!(seen.get(A).unwrap().name, "TV");
        assert_eq!(
            seen.addrs(A),
            [
                addr("192.168.1.5:1"),
                addr("127.0.0.1:11"),
                addr("127.0.0.1:9")
            ]
        );
    }

    #[test]
    fn a_case_only_rename_retires_nothing() {
        assert!(!retires(
            "A [x]._nodeinnet._tcp.local.",
            "a [x]._nodeinnet._tcp.local."
        ));
        assert!(retires(
            "A [x]._nodeinnet._tcp.local.",
            "B [x]._nodeinnet._tcp.local."
        ));
    }
}
