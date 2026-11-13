use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::lan::id;

pub const VERSION: u32 = 1;
pub const TRUSTED_MAX: usize = 32;
pub const PAIRED_MAX: usize = 64;
pub const BLOCKED_MAX: usize = 64;
pub const ADDRS_MAX: usize = 3;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Grants {
    pub terminal: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRecord {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub os: String,
    pub key: String,
    pub added: u64,
    #[serde(default)]
    pub last_seen: u64,
    #[serde(default)]
    pub last_addr: Option<String>,
    #[serde(default)]
    pub grants: Grants,
    #[serde(skip)]
    pub session_only: bool,
}

impl fmt::Debug for TrustRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("last_addr", &self.last_addr)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedRecord {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub os: String,
    pub key: String,
    #[serde(default)]
    pub last_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
    pub added: u64,
}

impl PairedRecord {
    pub fn addresses(&self) -> Vec<SocketAddr> {
        (self.last_addr.iter().chain(&self.addrs))
            .filter_map(|addr| addr.parse().ok())
            .collect()
    }
}

impl fmt::Debug for PairedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairedRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("last_addr", &self.last_addr)
            .field("addrs", &self.addrs)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRecord {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub addr: Option<String>,
    pub added: u64,
}

#[derive(Serialize, Deserialize)]
struct BookFile {
    v: u32,
    #[serde(default)]
    trusted: Vec<TrustRecord>,
    #[serde(default)]
    paired: Vec<PairedRecord>,
    #[serde(default)]
    blocked: Vec<BlockRecord>,
}

pub struct Book {
    store: Arc<dyn TrustStore>,
    pub trusted: Vec<TrustRecord>,
    pub paired: Vec<PairedRecord>,
    pub blocked: Vec<BlockRecord>,
}

impl fmt::Debug for Book {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Book")
            .field("trusted", &self.trusted)
            .field("paired", &self.paired)
            .field("blocked", &self.blocked)
            .finish_non_exhaustive()
    }
}

impl Book {
    pub fn open(store: Arc<dyn TrustStore>, log: &dyn Fn(&str)) -> io::Result<Book> {
        if let Some(doc) = store.load()? {
            match Self::parse(&store, &doc) {
                Ok(book) => return Ok(book),
                Err(why) => {
                    store.set_aside()?;
                    log(&format!(
                        "lan: the trust book is unreadable ({why}); set aside, nobody is trusted"
                    ));
                }
            }
        }
        Ok(Book {
            store,
            trusted: Vec::new(),
            paired: Vec::new(),
            blocked: Vec::new(),
        })
    }

    fn parse(store: &Arc<dyn TrustStore>, doc: &str) -> serde_json::Result<Book> {
        let file: BookFile = serde_json::from_str(doc)?;
        Ok(Book {
            store: store.clone(),
            trusted: file.trusted,
            paired: file.paired,
            blocked: file.blocked,
        })
    }

    pub fn save(&self) -> io::Result<()> {
        let file = BookFile {
            v: VERSION,
            trusted: (self.trusted.iter())
                .filter(|record| !record.session_only)
                .cloned()
                .collect(),
            paired: self.paired.clone(),
            blocked: self.blocked.clone(),
        };
        let mut doc = serde_json::to_string_pretty(&file).map_err(io::Error::other)?;
        doc.push('\n');
        self.store.save(&doc)
    }

    pub fn trusted(&self, id: &str) -> Option<&TrustRecord> {
        self.trusted.iter().find(|record| record.id == id)
    }

    pub fn trust(&mut self, record: TrustRecord) -> Option<TrustRecord> {
        self.trusted.retain(|old| old.id != record.id);
        let oldest = (0..self.trusted.len())
            .min_by_key(|&i| self.trusted[i].last_seen.max(self.trusted[i].added));
        let evicted = match oldest {
            Some(oldest) if self.trusted.len() >= TRUSTED_MAX => Some(self.trusted.remove(oldest)),
            _ => None,
        };
        self.trusted.push(record);
        evicted
    }

    pub fn revoke(&mut self, id: &str) -> Option<TrustRecord> {
        let i = self.trusted.iter().position(|record| record.id == id)?;
        Some(self.trusted.remove(i))
    }

    pub fn seen(&mut self, index: usize, ip: IpAddr, now: u64) -> (bool, bool) {
        let Some(record) = self.trusted.get_mut(index) else {
            return (false, false);
        };
        let ip = ip.to_canonical().to_string();
        let moved = record.last_addr.as_deref() != Some(ip.as_str());
        let new_address = moved && record.last_addr.is_some();
        record.last_seen = now;
        if moved {
            record.last_addr = Some(ip);
        }
        (new_address, moved)
    }

    pub fn set_grants(&mut self, id: &str, grants: Grants) -> bool {
        let Some(record) = self.trusted.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        let changed = record.grants != grants;
        record.grants = grants;
        changed
    }

    pub fn paired(&self, id: &str) -> Option<&PairedRecord> {
        self.paired.iter().find(|record| record.id == id)
    }

    pub fn pair(&mut self, record: PairedRecord) {
        self.paired.retain(|old| old.id != record.id);
        if self.paired.len() >= PAIRED_MAX {
            if let Some(oldest) = (0..self.paired.len()).min_by_key(|&i| self.paired[i].added) {
                self.paired.remove(oldest);
            }
        }
        self.paired.push(record);
    }

    pub fn unpair(&mut self, id: &str) -> Option<PairedRecord> {
        let i = self.paired.iter().position(|record| record.id == id)?;
        Some(self.paired.remove(i))
    }

    pub fn seen_at(&mut self, id: &str, addr: SocketAddr) -> bool {
        let addr = addr.to_string();
        let Some(record) = self.paired.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        if record.last_addr.as_deref() == Some(addr.as_str()) {
            return false;
        }
        record.addrs.retain(|old| *old != addr);
        if let Some(old) = record.last_addr.replace(addr) {
            record.addrs.insert(0, old);
        }
        record.addrs.truncate(ADDRS_MAX);
        true
    }

    pub fn forget_addr(&mut self, id: &str, addr: SocketAddr) -> bool {
        let addr = addr.to_string();
        let Some(record) = self.paired.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        let before = record.addrs.len();
        record.addrs.retain(|old| *old != addr);
        let mut changed = record.addrs.len() != before;
        if record.last_addr.as_deref() == Some(addr.as_str()) {
            record.last_addr = (!record.addrs.is_empty()).then(|| record.addrs.remove(0));
            changed = true;
        }
        changed
    }

    pub fn block(&mut self, record: BlockRecord) {
        self.blocked.retain(|old| old.id != record.id);
        if self.blocked.len() >= BLOCKED_MAX {
            self.blocked.remove(0);
        }
        self.blocked.push(record);
    }

    pub fn unblock(&mut self, id: &str) -> bool {
        let before = self.blocked.len();
        self.blocked.retain(|record| record.id != id);
        self.blocked.len() != before
    }

    pub fn is_blocked(&self, id: &str, ip: IpAddr) -> bool {
        let ip = ip.to_canonical().to_string();
        self.blocked
            .iter()
            .any(|record| record.id == id || record.addr.as_deref() == Some(ip.as_str()))
    }

    pub fn trusted_key(&self, key: &[u8; 32]) -> Option<usize> {
        let key = id::b64(key);
        self.trusted.iter().position(|record| record.key == key)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub trait TrustStore: Send + Sync {
    fn load(&self) -> io::Result<Option<String>>;
    fn save(&self, doc: &str) -> io::Result<()>;
    fn set_aside(&self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct FileTrustStore {
    path: PathBuf,
}

impl FileTrustStore {
    pub fn new(path: impl Into<PathBuf>) -> FileTrustStore {
        FileTrustStore { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl TrustStore for FileTrustStore {
    fn load(&self) -> io::Result<Option<String>> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn save(&self, doc: &str) -> io::Result<()> {
        write_atomic(&self.path, doc.as_bytes())
    }

    fn set_aside(&self) -> io::Result<()> {
        let bad = bad_path(&self.path);
        fs::rename(&self.path, &bad)?;
        restrict(&bad);
        Ok(())
    }
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(
        ".{name}.{}.tmp",
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 6]>())
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let result = written.and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn bad_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".bad");
    path.with_file_name(name)
}

fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const STORE_FILE: &str = "nodeinnet-lan.json";

    fn quiet(_: &str) {}

    fn on_disk(path: &Path) -> Arc<dyn TrustStore> {
        Arc::new(FileTrustStore::new(path))
    }

    fn trust_record(id: &str, seen: u64) -> TrustRecord {
        TrustRecord {
            id: id.into(),
            name: format!("dev {id}"),
            kind: "phone".into(),
            os: "android".into(),
            key: id::b64(&[7; 32]),
            added: 1,
            last_seen: seen,
            last_addr: None,
            grants: Grants::default(),
            session_only: false,
        }
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn fresh_reload_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join(STORE_FILE);
        let mut store = Book::open(on_disk(&path), &quiet).unwrap();
        assert!(store.trusted.is_empty() && !path.exists());
        store.trust(trust_record("a", 5));
        store.pair(PairedRecord {
            id: "b".into(),
            name: "TV".into(),
            kind: "tv".into(),
            os: "android".into(),
            key: "k".into(),
            last_addr: Some("192.168.1.30:47800".into()),
            addrs: vec!["192.168.1.17:47800".into()],
            added: 2,
        });
        store.save().unwrap();
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);

        let again = Book::open(on_disk(&path), &quiet).unwrap();
        assert_eq!(again.trusted, store.trusted);
        assert_eq!(again.paired, store.paired);
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn a_magnet_player_file_loads_without_its_key_and_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STORE_FILE);
        let key = id::b64(&[9; 32]);
        let old = serde_json::json!({"v": 1, "key": "MC4CAQAwBQYDK2VwBCIEIA",
            "trusted": [{"id": "a", "name": "Phone", "key": key, "token_sha256": "ab",
                "added": 1, "last_seen": 2, "last_addr": "192.168.1.20"}],
            "paired": [{"id": "b", "name": "TV", "key": key, "token": "secret",
                "last_addr": "192.168.1.30:47800", "added": 1}]});
        fs::write(&path, old.to_string()).unwrap();
        let store = Book::open(on_disk(&path), &quiet).unwrap();
        assert_eq!(store.trusted_key(&[9; 32]), Some(0));
        assert_eq!(store.paired("b").unwrap().key, key);
        store.save().unwrap();
        let written = fs::read_to_string(&path).unwrap();
        assert!(!written.contains("token") && !written.contains("secret"));
        assert!(!written.contains("MC4C"));
    }

    #[test]
    fn the_format_of_the_book() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STORE_FILE);
        let key = id::b64(&[9; 32]);
        let book = serde_json::json!({"v": 1,
            "trusted": [{"id": "a", "name": "Phone", "kind": "phone", "os": "android", "key": key,
                "added": 1, "last_seen": 2, "last_addr": "192.168.1.20", "grants": {"terminal": true}}],
            "paired": [{"id": "b", "name": "TV", "kind": "tv", "os": "android", "key": key,
                "last_addr": "192.168.1.30:47800", "addrs": ["192.168.1.17:47800"], "added": 1}],
            "blocked": [{"id": "c", "name": "Evil", "addr": "192.168.1.66", "added": 1}]});
        fs::write(&path, book.to_string()).unwrap();
        let store = Book::open(on_disk(&path), &quiet).unwrap();
        assert!(store.trusted("a").unwrap().grants.terminal);
        assert_eq!(store.paired("b").unwrap().addresses().len(), 2);
        assert!(store.is_blocked("c", "10.0.0.1".parse().unwrap()));
        store.save().unwrap();
        let written: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(written, book);

        let bare = br#"{"v":1,"trusted":[{"id":"a","name":"","key":"","added":1}]}"#;
        fs::write(&path, bare).unwrap();
        let store = Book::open(on_disk(&path), &quiet).unwrap();
        assert_eq!(store.trusted("a").unwrap().grants, Grants::default());
    }

    #[test]
    fn corrupt_goes_to_bad() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(STORE_FILE);
        fs::write(&path, b"{\"v\":1,\"key\":").unwrap();
        let logged = std::cell::RefCell::new(String::new());
        let store = Book::open(on_disk(&path), &|line| logged.borrow_mut().push_str(line)).unwrap();
        assert!(logged.borrow().contains("nobody is trusted"));
        let bad = dir.path().join(format!("{}.bad", STORE_FILE));
        assert_eq!(fs::read(&bad).unwrap(), b"{\"v\":1,\"key\":");
        #[cfg(unix)]
        assert_eq!(mode(&bad), 0o600);
        assert!(store.trusted.is_empty() && store.paired.is_empty() && store.blocked.is_empty());

        let not_a_book = br#"{"v":1,"trusted":[{"id":"a"}]}"#;
        fs::write(&path, not_a_book).unwrap();
        let mut fresh = Book::open(on_disk(&path), &quiet).unwrap();
        assert!(fresh.trusted("a").is_none());
        fresh.trust(trust_record("b", 1));
        fresh.save().unwrap();
        assert_eq!(fs::read(&bad).unwrap(), not_a_book);
        let again = Book::open(on_disk(&path), &quiet).unwrap();
        assert!(again.trusted("b").is_some());
    }

    #[test]
    fn temp_files_are_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.json");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        #[cfg(unix)]
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn caps_and_lists() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Book::open(on_disk(&dir.path().join("s.json")), &quiet).unwrap();
        for i in 0..TRUSTED_MAX {
            assert!(store
                .trust(trust_record(&i.to_string(), 100 + i as u64))
                .is_none());
        }
        assert!(store.trust(trust_record("5", 1000)).is_none());
        let evicted = store.trust(trust_record("new", 2000)).unwrap();
        assert_eq!(evicted.id, "0");
        assert_eq!(store.trusted.len(), TRUSTED_MAX);
        assert_eq!(store.trusted_key(&[7; 32]), Some(0));
        assert_eq!(store.trusted_key(&[8; 32]), None);
        assert!(store.revoke("new").is_some());
        assert!(store.revoke("new").is_none());

        store.block(BlockRecord {
            id: "evil".into(),
            name: "Evil".into(),
            addr: Some("192.168.1.66".into()),
            added: 1,
        });
        assert!(store.is_blocked("evil", "10.0.0.1".parse().unwrap()));
        assert!(store.is_blocked("other", "::ffff:192.168.1.66".parse().unwrap()));
        assert!(!store.is_blocked("other", "192.168.1.67".parse().unwrap()));
        assert!(store.unblock("evil"));
        assert!(!store.unblock("evil"));
    }

    #[test]
    fn paired_and_blocked_caps() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Book::open(on_disk(&dir.path().join("s.json")), &quiet).unwrap();
        for i in 0..=PAIRED_MAX {
            store.pair(PairedRecord {
                id: i.to_string(),
                added: 1000 - i as u64,
                ..paired_record(None)
            });
        }
        assert_eq!(store.paired.len(), PAIRED_MAX);
        assert!(store.paired(&PAIRED_MAX.to_string()).is_some());
        assert!(store.paired(&(PAIRED_MAX - 1).to_string()).is_none());
        for i in 0..=BLOCKED_MAX {
            store.block(BlockRecord {
                id: i.to_string(),
                name: String::new(),
                addr: None,
                added: 1,
            });
        }
        assert_eq!(store.blocked.len(), BLOCKED_MAX);
        assert!(!store.is_blocked("0", "10.0.0.1".parse().unwrap()));
        assert!(store.is_blocked(&BLOCKED_MAX.to_string(), "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn seen_alone_is_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let mut store = Book::open(on_disk(&path), &quiet).unwrap();
        store.trust(trust_record("a", 0));
        let lan = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(store.seen(0, lan("192.168.1.20"), 1000), (false, true));
        assert_eq!(store.seen(0, lan("192.168.1.20"), 1030), (false, false));
        assert_eq!(store.seen(0, lan("192.168.1.20"), 1061), (false, false));
        assert_eq!(store.seen(0, lan("192.168.1.21"), 1062), (true, true));
        assert_eq!(store.trusted[0].last_addr.as_deref(), Some("192.168.1.21"));
        assert_eq!(store.seen(7, lan("192.168.1.21"), 1062), (false, false));

        assert_eq!(store.seen(0, lan("192.168.1.21"), 99_000), (false, false));
        store.block(BlockRecord {
            id: "evil".into(),
            name: "Evil".into(),
            addr: None,
            added: 1,
        });
        store.save().unwrap();
        let again = Book::open(on_disk(&path), &quiet).unwrap();
        assert_eq!(again.trusted[0].last_seen, 99_000);
    }

    #[test]
    fn grants_and_trust_for_this_session_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let mut store = Book::open(on_disk(&path), &quiet).unwrap();
        store.trust(trust_record("a", 1));
        store.trust(TrustRecord {
            session_only: true,
            ..trust_record("b", 1)
        });
        assert!(store.set_grants("a", Grants { terminal: true }));
        assert!(!store.set_grants("a", Grants { terminal: true }));
        assert!(!store.set_grants("x", Grants { terminal: true }));
        store.save().unwrap();

        let again = Book::open(on_disk(&path), &quiet).unwrap();
        assert!(again.trusted("a").unwrap().grants.terminal);
        assert!(again.trusted("b").is_none());
        assert!(store.trusted("b").is_some());

        store.trust(trust_record("b", 2));
        store.save().unwrap();
        let again = Book::open(on_disk(&path), &quiet).unwrap();
        assert!(again.trusted("b").is_some());
    }

    #[derive(Default)]
    struct Memory {
        doc: Mutex<Option<String>>,
        refuse: bool,
    }

    impl TrustStore for Memory {
        fn load(&self) -> io::Result<Option<String>> {
            Ok(self.doc.lock().unwrap().clone())
        }

        fn save(&self, doc: &str) -> io::Result<()> {
            if self.refuse {
                return Err(io::Error::other("refused"));
            }
            *self.doc.lock().unwrap() = Some(doc.to_string());
            Ok(())
        }
    }

    #[test]
    fn a_backend_stores_only_the_text() {
        let memory = Arc::new(Memory::default());
        *memory.doc.lock().unwrap() = Some("[]".into());
        let logged = std::cell::RefCell::new(String::new());
        let mut store =
            Book::open(memory.clone(), &|line| logged.borrow_mut().push_str(line)).unwrap();
        assert!(logged.borrow().contains("nobody is trusted"));
        assert!(store.trusted.is_empty());
        assert_eq!(memory.doc.lock().unwrap().as_deref(), Some("[]"));
        store.trust(trust_record("a", 1));
        store.save().unwrap();
        let again = Book::open(memory.clone(), &quiet).unwrap();
        assert_eq!(again.trusted, store.trusted);

        let refusing = Arc::new(Memory {
            refuse: true,
            ..Memory::default()
        });
        let mut store = Book::open(refusing.clone(), &quiet).unwrap();
        store.trust(trust_record("a", 1));
        assert!(store.save().is_err());
        assert!(store.trusted("a").is_some());
        assert!(refusing.doc.lock().unwrap().is_none());
    }

    fn paired_record(last: Option<&str>) -> PairedRecord {
        PairedRecord {
            id: "b".into(),
            name: "TV".into(),
            kind: "tv".into(),
            os: "android".into(),
            key: "k".into(),
            last_addr: last.map(Into::into),
            addrs: Vec::new(),
            added: 1,
        }
    }

    #[test]
    fn paired_addresses_follow_the_device() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let mut store = Book::open(on_disk(&path), &quiet).unwrap();
        store.pair(paired_record(Some("192.168.1.30:47800")));
        let at = |s: &str| s.parse::<SocketAddr>().unwrap();
        let strings = |store: &Book| {
            let record = store.paired("b").unwrap();
            (
                record.last_addr.clone().unwrap_or_default(),
                record.addrs.join(" "),
            )
        };
        assert!(!store.seen_at("b", at("192.168.1.30:47800")));
        assert!(!store.seen_at("x", at("192.168.1.31:47800")));
        for last in 31..=35 {
            assert!(store.seen_at("b", at(&format!("192.168.1.{last}:47800"))));
        }
        assert_eq!(
            strings(&store),
            (
                "192.168.1.35:47800".into(),
                "192.168.1.34:47800 192.168.1.33:47800 192.168.1.32:47800".into()
            )
        );
        assert!(store.seen_at("b", at("192.168.1.33:47800")));
        assert_eq!(
            strings(&store).1,
            "192.168.1.35:47800 192.168.1.34:47800 192.168.1.32:47800"
        );
        assert_eq!(store.paired("b").unwrap().addresses().len(), 4);

        store.save().unwrap();
        let again = Book::open(on_disk(&path), &quiet).unwrap();
        assert_eq!(strings(&again), strings(&store));
        let mut file: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let record = file["paired"][0].as_object_mut().unwrap();
        assert!(record.remove("addrs").is_some());
        fs::write(&path, file.to_string()).unwrap();
        let old = Book::open(on_disk(&path), &quiet).unwrap();
        assert!(old.paired("b").unwrap().addrs.is_empty());
        assert_eq!(
            old.paired("b").unwrap().last_addr.as_deref(),
            Some("192.168.1.33:47800")
        );
        old.save().unwrap();
        assert!(!fs::read_to_string(&path).unwrap().contains("addrs"));

        assert!(store.forget_addr("b", at("192.168.1.34:47800")));
        assert!(!store.forget_addr("b", at("192.168.1.34:47800")));
        assert!(store.forget_addr("b", at("192.168.1.33:47800")));
        assert_eq!(
            strings(&store),
            ("192.168.1.35:47800".into(), "192.168.1.32:47800".into())
        );
        let mut store = Book::open(on_disk(&dir.path().join("t.json")), &quiet).unwrap();
        store.pair(paired_record(Some("192.168.1.30:47800")));
        assert!(store.forget_addr("b", at("192.168.1.30:47800")));
        assert_eq!(store.paired("b").unwrap().last_addr, None);
    }
}
