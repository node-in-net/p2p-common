pub mod id;
mod mdns;
pub mod net;
pub mod pairing;
pub mod sas;
pub mod store;
mod tunnel;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures_util::FutureExt as _;
use mdns_sd::ServiceEvent;
use nodeinnet_p2p::{NodeInfo, RtcSignal, SharedResource};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinSet};

pub use pairing::RefuseCode;
pub use store::{FileTrustStore, Grants, TrustStore};

use pairing::{Answer, Answered, Context, Pairing};
use store::{BlockRecord, Book, PairedRecord, TrustRecord};
use tunnel::{Answerer, Asker, Established, LanFrame, Role, Step, TunnelError, WireOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Off,
    TrustedOnly,
    Open,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    Account,
    Lan { key: [u8; 32] },
}

#[derive(Clone)]
pub struct LanConfig {
    pub name: String,
    pub os: String,
    pub kind: String,
    pub visibility: Visibility,
    pub browse: bool,
    pub port: u16,
    pub resources: Vec<SharedResource>,
    pub trust: Arc<dyn TrustStore>,
    pub test_mode: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairDecision {
    Allow { remember: bool },
    Deny,
    Block,
}

pub struct PairReply(oneshot::Sender<PairDecision>);

impl PairReply {
    pub fn new(sender: oneshot::Sender<PairDecision>) -> PairReply {
        PairReply(sender)
    }

    pub fn answer(self, decision: PairDecision) {
        let _ = self.0.send(decision);
    }
}

impl fmt::Debug for PairReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairReply")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairPrompt {
    pub request: String,
    pub id: String,
    pub fingerprint: String,
    pub name: String,
    pub os: String,
    pub kind: String,
    pub addr: IpAddr,
    pub code: String,
    pub known: bool,
    pub name_clash: bool,
    pub quiet: bool,
    pub expires_in: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairOutcome {
    Allowed,
    Denied,
    Expired,
    Cancelled,
    NotShown,
    Refused {
        code: RefuseCode,
        retry_after: Option<Duration>,
    },
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct LanDevice {
    pub id: String,
    pub fingerprint: String,
    pub name: String,
    pub os: String,
    pub kind: String,
    pub online: bool,
    pub name_verified: bool,
    pub name_clash: bool,
    pub may_open_me: Option<Grants>,
    pub opened_from_here: bool,
    pub resources: Vec<SharedResource>,
    pub last_seen: u64,
}

#[derive(Clone, Debug)]
pub struct LanState {
    pub me: String,
    pub port: u16,
    pub visibility: Visibility,
    pub paused: bool,
    pub devices: Vec<LanDevice>,
    pub blocked: Vec<LanDevice>,
    pub pending: Vec<PairPrompt>,
}

#[derive(Clone, Debug)]
pub enum LanEvent {
    State(LanState),
    PairWaiting { id: String, code: String },
    PairDone { id: String, outcome: PairOutcome },
    PromptClosed { request: String },
    Unpaired { id: String },
    OpenFailed { id: String, reason: String },
    NotSaved(String),
    Failed(String),
}

#[derive(Debug)]
pub enum LanSignal {
    Rtc {
        id: String,
        key: [u8; 32],
        signal: RtcSignal,
    },
    Close {
        id: String,
    },
    Unreachable {
        id: String,
        dial: u64,
        reason: String,
    },
    Prompt(PairPrompt, PairReply),
    Event(LanEvent),
    Log(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    pub key: [u8; 32],
    pub dial: u64,
}

struct Unwritable(String);

impl TrustStore for Unwritable {
    fn load(&self) -> io::Result<Option<String>> {
        Ok(None)
    }

    fn save(&self, _doc: &str) -> io::Result<()> {
        Err(io::Error::other(self.0.clone()))
    }
}

struct Checked(Arc<dyn TrustStore>);

impl TrustStore for Checked {
    fn load(&self) -> io::Result<Option<String>> {
        let doc = self.0.load()?;
        let version = (doc.as_deref())
            .and_then(|doc| serde_json::from_str::<serde_json::Value>(doc).ok())
            .and_then(|value| value.get("v").and_then(serde_json::Value::as_f64));
        if version.is_some_and(|v| v > f64::from(store::VERSION)) {
            return Err(io::Error::other("it was written by a newer version"));
        }
        Ok(doc)
    }

    fn save(&self, doc: &str) -> io::Result<()> {
        self.0.save(doc)
    }

    fn set_aside(&self) -> io::Result<()> {
        self.0.set_aside()
    }
}

fn wanted(visibility: Visibility, any_trusted: bool, unreadable: bool) -> (bool, bool) {
    if unreadable {
        return (false, false);
    }
    match visibility {
        Visibility::Open => (true, true),
        Visibility::TrustedOnly => (any_trusted, false),
        Visibility::Off => (false, false),
    }
}

fn skeleton(name: &str) -> String {
    (name.chars())
        .filter(|&c| !c.is_whitespace() && !c.is_control() && !ignorable(c))
        .flat_map(char::to_lowercase)
        .collect()
}

fn ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

fn name_or_default(name: &str) -> String {
    let name = id::sanitize_name(name);
    if !name.is_empty() {
        return name;
    }
    let host = hostname::get()
        .map(|host| id::sanitize_name(&host.to_string_lossy()))
        .unwrap_or_default();
    if !host.is_empty() {
        return host;
    }
    "Node In Net".to_string()
}

fn account_names(nodes: &[NodeInfo]) -> Vec<(String, String)> {
    (nodes.iter())
        .filter_map(|node| Some((id::id_of(&node.public_key)?, skeleton(&node.name))))
        .collect()
}

fn unix_time(at: Instant, now: Instant) -> u64 {
    store::now().saturating_sub(now.saturating_duration_since(at).as_secs())
}

pub struct Lan {
    me: tunnel::Identity,
    test_mode: bool,
    on_link: Arc<net::OnLink>,
    handle: Handle,
    signals: mpsc::Sender<LanSignal>,
    up: mpsc::UnboundedSender<Up>,
    inner: Mutex<Inner>,
    tasks: Mutex<JoinSet<()>>,
    slots: Arc<tunnel::Slots>,
    state_queued: AtomicBool,
    stopping: AtomicBool,
}

enum Up {
    Signal(Box<LanSignal>),
    State,
}

struct Inner {
    card: tunnel::Card,
    config_port: u16,
    visibility: Visibility,
    browse: bool,
    unreadable: bool,
    book: Book,
    pairing: Pairing,
    seen: mdns::Seen,
    mdns: Option<mdns::Mdns>,
    mdns_failed: bool,
    listening: Option<Listening>,
    last_port: Option<u16>,
    tunnels: Vec<Tunnel>,
    serial: u64,
    dial_seq: u64,
    attempt: u64,
    opening: HashMap<String, Opening>,
    outgoing: Option<OutgoingPair>,
    prompts: HashMap<String, Raised>,
    hellos: Vec<(tunnel::Peer, u64)>,
    sessions: HashMap<String, Vec<SharedResource>>,
    account: Vec<(String, String)>,
}

struct Listening {
    port: u16,
    task: AbortHandle,
}

struct Opening {
    dial: u64,
    key: [u8; 32],
    queue: Vec<RtcSignal>,
    task: AbortHandle,
}

struct OutgoingPair {
    id: String,
    attempt: u64,
    serial: Option<u64>,
    dial: Option<AbortHandle>,
}

struct Raised {
    prompt: PairPrompt,
    expires: Instant,
    reply: AbortHandle,
}

struct Tunnel {
    serial: u64,
    peer: tunnel::Peer,
    addr: SocketAddr,
    outbound: bool,
    admitted: bool,
    h: [u8; 32],
    registered: Instant,
    tx: mpsc::Sender<LanFrame>,
    reader: Option<AbortHandle>,
    slot: Option<tunnel::Slot>,
    asker: Option<Asker>,
    answerer: Option<Answerer>,
    warned: bool,
}

enum Next {
    Go,
    Stop,
    Signal(Box<LanSignal>),
}

enum Due {
    Asker(Step),
    Challenged { request: String, from: String },
    Undecided(String),
    Unconfirmed,
    Stranger,
}

type Dialled = (SocketAddr, Established<OwnedReadHalf, OwnedWriteHalf>);

const HELLOS_MAX: usize = 64;
const CANDIDATES_MAX: usize = 6;
const OPEN_QUEUE_MAX: usize = 64;
const TICK: Duration = Duration::from_secs(1);

fn deadline(t: &Tunnel) -> Option<Instant> {
    match (&t.asker, &t.answerer) {
        (Some(asker), _) => Some(asker.until()),
        (None, Some(answerer)) => Some(answerer.until()),
        (None, None) => {
            (!t.admitted && !t.outbound).then_some(t.registered + tunnel::STRANGER_START)
        }
    }
}

impl Inner {
    fn tunnel(&self, serial: u64) -> Option<&Tunnel> {
        self.tunnels.iter().find(|t| t.serial == serial)
    }

    fn tunnel_mut(&mut self, serial: u64) -> Option<&mut Tunnel> {
        self.tunnels.iter_mut().find(|t| t.serial == serial)
    }

    fn serials(&self, pick: impl Fn(&Tunnel) -> bool) -> Vec<u64> {
        (self.tunnels.iter())
            .filter(|t| pick(t))
            .map(|t| t.serial)
            .collect()
    }

    fn answering(&self, request: &str) -> Option<u64> {
        (self.tunnels.iter())
            .find(|t| (t.answerer.as_ref()).is_some_and(|a| a.request() == request))
            .map(|t| t.serial)
    }

    fn candidates(&self, on_link: &net::OnLink, id: &str, now: Instant) -> Vec<SocketAddr> {
        let stored = self.book.paired(id).map(PairedRecord::addresses);
        let mut addrs: Vec<SocketAddr> = Vec::new();
        for addr in stored
            .unwrap_or_default()
            .into_iter()
            .chain(self.seen.addrs(id))
        {
            if !addrs.contains(&addr) && !self.seen.is_bad(id, addr, now) {
                addrs.push(addr);
            }
        }
        let mut ordered = net::order_addrs(on_link, addrs);
        ordered.truncate(CANDIDATES_MAX);
        ordered
    }

    fn clash(&self, id: &str, name: &str) -> bool {
        let wanted = skeleton(name);
        if wanted.is_empty() {
            return false;
        }
        let other = |other: &str, name: &str| other != id && skeleton(name) == wanted;
        self.seen.devices().any(|e| other(&e.id, &e.name))
            || self.book.trusted.iter().any(|r| other(&r.id, &r.name))
            || self.book.paired.iter().any(|r| other(&r.id, &r.name))
            || self.hellos.iter().any(|(p, _)| other(&p.id, &p.name))
            || (self.account.iter()).any(|(account, name)| account != id && *name == wanted)
    }

    fn verified(&self, id: &str) -> Option<(&str, &str, &str)> {
        let hello = self.hellos.iter().find(|(p, _)| p.id == id);
        (hello.map(|(p, _)| (p.name.as_str(), p.os.as_str(), p.kind.as_str())))
            .or_else(|| {
                (self.book.trusted(id)).map(|r| (r.name.as_str(), r.os.as_str(), r.kind.as_str()))
            })
            .or_else(|| {
                (self.book.paired(id)).map(|r| (r.name.as_str(), r.os.as_str(), r.kind.as_str()))
            })
    }

    fn name_of(&self, id: &str) -> String {
        let verified = self.verified(id).map(|(name, _, _)| name);
        let seen = self.seen.get(id).map(|e| e.name.as_str());
        verified.or(seen).unwrap_or(id::id8(id)).to_string()
    }

    fn device(&self, id: &str, now: Instant) -> (bool, LanDevice) {
        let trusted = self.book.trusted(id);
        let paired = self.book.paired(id);
        let seen = self.seen.get(id);
        let hello = self.hellos.iter().find(|(p, _)| p.id == id);
        let verified = self.verified(id);
        let (name, os, kind) = verified
            .or_else(|| seen.map(|e| (e.name.as_str(), e.os.as_str(), e.kind.as_str())))
            .unwrap_or((id::id8(id), "", ""));
        let last_seen = [
            trusted.map(|r| r.last_seen),
            hello.map(|(_, at)| *at),
            seen.map(|e| unix_time(e.seen, now)),
        ];
        let device = LanDevice {
            id: id.to_string(),
            fingerprint: id::fingerprint(id),
            name: name.to_string(),
            os: os.to_string(),
            kind: kind.to_string(),
            online: self.seen.has(id) || self.tunnels.iter().any(|t| t.peer.id == id),
            name_verified: verified.is_some(),
            name_clash: self.clash(id, name),
            may_open_me: trusted.map(|r| r.grants),
            opened_from_here: paired.is_some(),
            resources: self.sessions.get(id).cloned().unwrap_or_default(),
            last_seen: last_seen.into_iter().flatten().max().unwrap_or(0),
        };
        (trusted.is_some() || paired.is_some(), device)
    }

    fn devices(&self, me: &str, now: Instant) -> Vec<LanDevice> {
        let blocked = |id: &str| self.book.blocked.iter().any(|r| r.id == id);
        let sources = (self.book.trusted.iter().map(|r| r.id.as_str()))
            .chain(self.book.paired.iter().map(|r| r.id.as_str()))
            .chain(self.seen.devices().map(|e| e.id.as_str()))
            .chain((self.tunnels.iter().filter(|t| t.admitted)).map(|t| t.peer.id.as_str()));
        let mut ids: Vec<&str> = Vec::new();
        for id in sources {
            if id != me && !blocked(id) && !ids.contains(&id) {
                ids.push(id);
            }
        }
        let mut devices: Vec<(bool, LanDevice)> =
            ids.into_iter().map(|id| self.device(id, now)).collect();
        devices.sort_by(|(a_known, a), (b_known, b)| {
            (b_known.cmp(a_known))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.id.cmp(&b.id))
        });
        devices.into_iter().map(|(_, device)| device).collect()
    }

    fn state(&self, me: &str, now: Instant) -> LanState {
        let mut pending: Vec<&Raised> = self.prompts.values().collect();
        pending.sort_by_key(|raised| raised.expires);
        let blocked = (self.book.blocked.iter()).map(|record| LanDevice {
            id: record.id.clone(),
            fingerprint: id::fingerprint(&record.id),
            name: record.name.clone(),
            os: String::new(),
            kind: String::new(),
            online: false,
            name_verified: false,
            name_clash: false,
            may_open_me: None,
            opened_from_here: false,
            resources: Vec::new(),
            last_seen: record.added,
        });
        LanState {
            me: me.to_string(),
            port: self.listening.as_ref().map_or(0, |l| l.port),
            visibility: self.visibility,
            paused: self.pairing.paused(now),
            devices: self.devices(me, now),
            blocked: blocked.collect(),
            pending: (pending.into_iter())
                .map(|raised| PairPrompt {
                    expires_in: raised.expires.saturating_duration_since(now),
                    ..raised.prompt.clone()
                })
                .collect(),
        }
    }
}

impl Lan {
    pub async fn start(
        config: LanConfig,
        private_key: &str,
        signals: mpsc::Sender<LanSignal>,
    ) -> io::Result<Arc<Lan>> {
        let handle =
            Handle::try_current().map_err(|_| io::Error::other("lan: no tokio runtime"))?;
        let me = tunnel::Identity::from_private(private_key)
            .map_err(|e| io::Error::other(format!("lan: the device key is unusable ({e})")))?;
        let (up, rx) = mpsc::unbounded_channel();
        let early = |signal| {
            let _ = up.send(Up::Signal(Box::new(signal)));
        };
        let on_link = Arc::new(net::OnLink::new(config.test_mode));
        if on_link.fallback() {
            early(LanSignal::Log(
                "⚠️ lan: the network interfaces could not be read; any private address is accepted"
                    .to_string(),
            ));
        }
        let lines = RefCell::new(Vec::new());
        let opened = Book::open(Arc::new(Checked(config.trust.clone())), &|line| {
            lines.borrow_mut().push(line.to_string())
        });
        let (book, unreadable) = match opened {
            Ok(book) => {
                for line in lines.take() {
                    early(LanSignal::Log(format!("⚠️ {line}")));
                    early(LanSignal::Event(LanEvent::NotSaved(line)));
                }
                (book, false)
            }
            Err(e) => {
                let unwritable = Unwritable(format!("the trust book could not be read ({e})"));
                let book = Book::open(Arc::new(unwritable), &|_| {})?;
                early(LanSignal::Event(LanEvent::NotSaved(format!(
                    "lan: the trust book cannot be read ({e}); this device takes no incoming connections and saves no pairing until it can"
                ))));
                (book, true)
            }
        };
        let card = tunnel::Card {
            name: name_or_default(&config.name),
            os: id::sanitize_name(&config.os),
            kind: id::sanitize_name(&config.kind),
        };
        let lan = Arc::new(Lan {
            me,
            test_mode: config.test_mode,
            on_link,
            handle,
            signals,
            up,
            inner: Mutex::new(Inner {
                card,
                config_port: config.port,
                visibility: config.visibility,
                browse: config.browse,
                unreadable,
                book,
                pairing: Pairing::default(),
                seen: mdns::Seen::default(),
                mdns: None,
                mdns_failed: false,
                listening: None,
                last_port: None,
                tunnels: Vec::new(),
                serial: 0,
                dial_seq: 0,
                attempt: 0,
                opening: HashMap::new(),
                outgoing: None,
                prompts: HashMap::new(),
                hellos: Vec::new(),
                sessions: HashMap::new(),
                account: Vec::new(),
            }),
            tasks: Mutex::new(JoinSet::new()),
            slots: Arc::new(tunnel::Slots::default()),
            state_queued: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
        });
        lan.spawn(lan.clone().forward(rx));
        lan.spawn(lan.clone().timer());
        {
            let mut guard = lan.lock();
            let inner = &mut *guard;
            lan.reconcile(inner);
            if inner.browse {
                lan.start_browse(inner);
            }
        }
        lan.changed();
        Ok(lan)
    }

    pub fn id(&self) -> &str {
        &self.me.id
    }

    pub fn port(&self) -> Option<u16> {
        self.lock().listening.as_ref().map(|l| l.port)
    }

    pub fn visibility(&self) -> Visibility {
        self.lock().visibility
    }

    pub fn grants(&self, id: &str) -> Option<Grants> {
        self.lock().book.trusted(id).map(|r| r.grants)
    }

    pub fn knows(&self, id: &str) -> bool {
        let inner = self.lock();
        inner.book.trusted(id).is_some() || inner.book.paired(id).is_some()
    }

    pub fn dialing(&self, id: &str) -> bool {
        self.lock().opening.contains_key(id)
    }

    pub fn state(&self) -> LanState {
        self.lock().state(&self.me.id, Instant::now())
    }

    pub fn open(self: &Arc<Self>, id: &str) -> Option<Opened> {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let key = inner.book.paired(id).and_then(|r| id::key_bytes(&r.key))?;
        let admitted = (inner.tunnels.iter()).find(|t| t.outbound && t.admitted && t.peer.id == id);
        if let Some(t) = admitted {
            return Some(Opened {
                key: t.peer.key,
                dial: 0,
            });
        }
        if let Some(opening) = inner.opening.get(id) {
            return Some(Opened {
                key: opening.key,
                dial: opening.dial,
            });
        }
        inner.dial_seq += 1;
        let dial = inner.dial_seq;
        let lan = self.clone();
        let target = id.to_string();
        let task = self.spawn(async move { lan.open_dial(target, dial).await })?;
        let opening = Opening {
            dial,
            key,
            queue: Vec::new(),
            task,
        };
        inner.opening.insert(id.to_string(), opening);
        Some(Opened { key, dial })
    }

    pub fn send_rtc(&self, id: &str, signal: RtcSignal) -> bool {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let dialing = inner.opening.contains_key(id);
        let tunnel = (inner.tunnels.iter())
            .filter(|t| t.admitted && t.peer.id == id && (t.outbound || !dialing))
            .min_by_key(|t| !t.outbound);
        if let Some(t) = tunnel {
            let serial = t.serial;
            return match t.tx.try_send(LanFrame::Rtc { signal }) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    self.close(inner, serial, false);
                    false
                }
                Err(TrySendError::Closed(_)) => false,
            };
        }
        match inner.opening.get_mut(id) {
            Some(opening) if opening.queue.len() < OPEN_QUEUE_MAX => {
                opening.queue.push(signal);
                true
            }
            _ => false,
        }
    }

    pub fn session(&self, id: &str, resources: Option<Vec<SharedResource>>) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        match resources {
            Some(resources) => {
                inner.sessions.insert(id.to_string(), resources);
            }
            None => {
                inner.sessions.remove(id);
                if let Some(opening) = inner.opening.remove(id) {
                    opening.task.abort();
                }
                let outbound =
                    inner.serials(|t| t.outbound && t.peer.id == id && t.asker.is_none());
                for serial in outbound {
                    self.close(inner, serial, false);
                }
            }
        }
        self.changed();
    }

    pub fn set_visibility(self: &Arc<Self>, visibility: Visibility) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        if inner.visibility == visibility {
            return;
        }
        inner.visibility = visibility;
        if visibility != Visibility::Open {
            for request in inner.pairing.end_all() {
                self.end_incoming(inner, &request, WireOutcome::Expired);
            }
            let unconfirmed = inner.serials(|t| {
                !t.admitted
                    && (t.answerer.as_ref()).is_some_and(|a| !a.challenged() && !a.undecided())
            });
            for serial in unconfirmed {
                self.end_answer(inner, serial, WireOutcome::Expired);
                self.close(inner, serial, false);
            }
        }
        let closing = match visibility {
            Visibility::TrustedOnly => inner.serials(|t| !t.outbound && !t.admitted),
            Visibility::Off => inner.serials(|t| !t.outbound),
            Visibility::Open => Vec::new(),
        };
        for serial in closing {
            self.close(inner, serial, false);
        }
        self.reconcile(inner);
        self.changed();
    }

    pub fn browse(self: &Arc<Self>, on: bool) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        inner.browse = on;
        if on {
            self.start_browse(inner);
        } else {
            if let Some(mdns) = inner.mdns.as_mut() {
                mdns.stop_browse();
            }
            inner.seen.clear();
        }
        self.changed();
    }

    pub fn set_name(&self, name: &str) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        inner.card.name = name_or_default(name);
        if inner.mdns.is_some() {
            self.advertise(inner);
        }
        self.changed();
    }

    pub fn set_account_nodes(&self, nodes: &[NodeInfo]) {
        let account = account_names(nodes);
        let mut inner = self.lock();
        if inner.account != account {
            inner.account = account;
            drop(inner);
            self.changed();
        }
    }

    pub fn pair(self: &Arc<Self>, id: &str) {
        if self.stopping() || id == self.me.id {
            return;
        }
        let mut guard = self.lock();
        let inner = &mut *guard;
        if inner.book.blocked.iter().any(|r| r.id == id) {
            self.event(LanEvent::PairDone {
                id: id.to_string(),
                outcome: PairOutcome::Failed("blocked here; unblock it first".to_string()),
            });
            return;
        }
        self.cancel_outgoing(inner, PairOutcome::Cancelled);
        inner.attempt += 1;
        let attempt = inner.attempt;
        let ready = (inner.tunnels.iter())
            .find(|t| t.outbound && t.admitted && t.peer.id == id && t.asker.is_none())
            .map(|t| t.serial);
        if let Some(serial) = ready {
            inner.outgoing = Some(OutgoingPair {
                id: id.to_string(),
                attempt,
                serial: Some(serial),
                dial: None,
            });
            self.start_asker(inner, serial);
        } else {
            let lan = self.clone();
            let target = id.to_string();
            let dial = self.spawn(async move { lan.pair_dial(target, attempt).await });
            inner.outgoing = Some(OutgoingPair {
                id: id.to_string(),
                attempt,
                serial: None,
                dial,
            });
        }
        self.changed();
    }

    pub fn confirm_pair(&self, id: &str, code: &str) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let outgoing = inner.outgoing.as_ref().filter(|o| o.id == id);
        let Some(serial) = outgoing.and_then(|o| o.serial) else {
            return;
        };
        let asker = inner.tunnel_mut(serial).and_then(|t| t.asker.as_mut());
        if let Some(step) = asker.and_then(|asker| asker.confirm(code)) {
            self.apply_asker(inner, serial, step);
        }
    }

    pub fn cancel_pair(&self, id: &str) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        if inner.outgoing.as_ref().is_some_and(|o| o.id == id) {
            self.cancel_outgoing(inner, PairOutcome::Cancelled);
        }
    }

    pub fn forget(self: &Arc<Self>, id: &str) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let revoked = inner.book.revoke(id).is_some();
        let unpaired = inner.book.unpair(id).is_some();
        if revoked || unpaired {
            self.save(inner);
        }
        self.drop_device(inner, id);
    }

    pub fn block(self: &Arc<Self>, id: &str) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let now = Instant::now();
        let name = inner.name_of(id);
        let addr = (inner.book.trusted(id))
            .and_then(|r| r.last_addr.clone())
            .or_else(|| {
                (inner.tunnels.iter())
                    .find(|t| t.peer.id == id)
                    .map(|t| t.addr.ip().to_string())
            });
        inner.book.block(BlockRecord {
            id: id.to_string(),
            name,
            addr,
            added: store::now(),
        });
        inner.book.revoke(id);
        inner.book.unpair(id);
        self.save(inner);
        for serial in inner.serials(|t| t.peer.id == id && t.answerer.is_some()) {
            let Some(request) = (inner.tunnel(serial))
                .and_then(|t| t.answerer.as_ref())
                .map(|a| a.request().to_string())
            else {
                continue;
            };
            inner.pairing.cancel(&request, id, now);
            self.end_answer(inner, serial, WireOutcome::Denied);
            self.close_prompt(inner, &request);
        }
        self.drop_device(inner, id);
    }

    pub fn unblock(&self, id: &str) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        if inner.book.unblock(id) {
            self.save(inner);
            self.changed();
        }
    }

    pub fn set_grants(&self, id: &str, grants: Grants) -> bool {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let changed = inner.book.set_grants(id, grants);
        if changed {
            self.save(inner);
            for serial in inner.serials(|t| t.peer.id == id) {
                self.close(inner, serial, false);
            }
            self.push(LanSignal::Close { id: id.to_string() });
            self.changed();
        }
        changed
    }

    pub fn resume_pairing(&self) {
        self.lock().pairing.resume();
        self.changed();
    }

    pub async fn stop(&self) {
        {
            let _tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
            if self.stopping.swap(true, Ordering::SeqCst) {
                return;
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mdns = {
            let mut guard = self.lock();
            let inner = &mut *guard;
            if let Some(listening) = inner.listening.take() {
                listening.task.abort();
            }
            for t in inner.tunnels.drain(..) {
                let _ = t.tx.try_send(LanFrame::Bye);
                if let Some(reader) = &t.reader {
                    reader.abort();
                }
            }
            for (_, raised) in inner.prompts.drain() {
                raised.reply.abort();
            }
            for (_, opening) in inner.opening.drain() {
                opening.task.abort();
            }
            if let Some(dial) = inner.outgoing.take().and_then(|o| o.dial) {
                dial.abort();
            }
            inner.mdns.take()
        };
        let goodbye = async {
            if let Some(mdns) = mdns {
                mdns.stop(deadline - Duration::from_millis(300)).await;
            }
        };
        tokio::join!(tokio::time::sleep(Duration::from_millis(100)), goodbye);
        let mut tasks =
            std::mem::take(&mut *self.tasks.lock().unwrap_or_else(PoisonError::into_inner));
        tasks.abort_all();
        let _ = tokio::time::timeout_at(deadline, tasks.shutdown()).await;
    }

    #[doc(hidden)]
    pub fn add_address(&self, id: &str, addr: SocketAddr) {
        self.lock().seen.inject(id, addr, Instant::now());
        self.changed();
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    fn push(&self, signal: LanSignal) {
        let _ = self.up.send(Up::Signal(Box::new(signal)));
    }

    fn event(&self, event: LanEvent) {
        self.push(LanSignal::Event(event));
    }

    fn changed(&self) {
        if !self.state_queued.swap(true, Ordering::SeqCst) {
            let _ = self.up.send(Up::State);
        }
    }

    fn spawn<F>(&self, task: F) -> Option<AbortHandle>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        if self.stopping() {
            return None;
        }
        while let Some(Some(_)) = tasks.join_next().now_or_never() {}
        Some(tasks.spawn_on(task, &self.handle))
    }

    async fn forward(self: Arc<Self>, mut rx: mpsc::UnboundedReceiver<Up>) {
        while let Some(up) = rx.recv().await {
            let signal = match up {
                Up::State => {
                    self.state_queued.store(false, Ordering::SeqCst);
                    LanSignal::Event(LanEvent::State(self.state()))
                }
                Up::Signal(signal) => *signal,
            };
            if self.signals.send(signal).await.is_err() {
                break;
            }
        }
    }

    async fn timer(self: Arc<Self>) {
        let mut interval = tokio::time::interval(TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            self.tick(Instant::now());
        }
    }

    fn save(&self, inner: &Inner) {
        if let Err(e) = inner.book.save() {
            self.event(LanEvent::NotSaved(format!(
                "lan: the trust book was not saved ({e})"
            )));
        }
    }

    fn reconcile(self: &Arc<Self>, inner: &mut Inner) {
        if self.stopping() {
            return;
        }
        let any_trusted = !inner.book.trusted.is_empty();
        let (listen, _) = wanted(inner.visibility, any_trusted, inner.unreadable);
        if listen && inner.listening.is_none() {
            match self.listen(inner) {
                Ok((listener, port)) => {
                    let lan = self.clone();
                    if let Some(task) = self.spawn(lan.accept_loop(listener)) {
                        inner.listening = Some(Listening { port, task });
                        inner.last_port = Some(port);
                    }
                }
                Err(e) => self.event(LanEvent::Failed(format!("❌ lan: cannot listen ({e})"))),
            }
        } else if !listen {
            if let Some(listening) = inner.listening.take() {
                listening.task.abort();
            }
        }
        self.advertise(inner);
    }

    fn listen(&self, inner: &Inner) -> io::Result<(TcpListener, u16)> {
        let any = Ipv4Addr::UNSPECIFIED;
        let bound = match inner.last_port {
            Some(port) => match net::bind_ladder(any, port, true) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::AddrInUse
                            | io::ErrorKind::AddrNotAvailable
                            | io::ErrorKind::PermissionDenied
                    ) =>
                {
                    net::bind_ladder(any, inner.config_port, false)
                }
                bound => bound,
            },
            None => net::bind_ladder(any, inner.config_port, false),
        }?;
        bound.set_nonblocking(true)?;
        let port = bound.local_addr()?.port();
        let _runtime = self.handle.enter();
        Ok((TcpListener::from_std(bound)?, port))
    }

    fn advertise(&self, inner: &mut Inner) {
        let any_trusted = !inner.book.trusted.is_empty();
        let (_, advertise) = wanted(inner.visibility, any_trusted, inner.unreadable);
        let now = Instant::now();
        let port = inner
            .listening
            .as_ref()
            .map(|l| l.port)
            .filter(|_| advertise);
        let Some(port) = port else {
            if let Some(mdns) = inner.mdns.as_mut() {
                let _ = mdns.advertise(None, now);
            }
            return;
        };
        if !self.ensure_mdns(inner) {
            return;
        }
        let advert = mdns::Advert {
            id: self.me.id.clone(),
            name: inner.card.name.clone(),
            os: inner.card.os.clone(),
            kind: inner.card.kind.clone(),
            port,
        };
        let advertised = (inner.mdns.as_mut()).map_or(Ok(()), |m| m.advertise(Some(advert), now));
        if let Err(e) = advertised {
            self.mdns_failed(inner, e);
        }
    }

    fn ensure_mdns(&self, inner: &mut Inner) -> bool {
        if inner.mdns.is_some() {
            return true;
        }
        if self.stopping() {
            return false;
        }
        match mdns::Mdns::new(self.test_mode) {
            Ok(mdns) => {
                inner.mdns = Some(mdns);
                true
            }
            Err(e) => {
                self.mdns_failed(inner, e);
                false
            }
        }
    }

    fn mdns_failed(&self, inner: &mut Inner, e: mdns_sd::Error) {
        if !std::mem::replace(&mut inner.mdns_failed, true) {
            self.event(LanEvent::Failed(format!(
                "❌ lan: mDNS is unavailable ({e})"
            )));
        }
    }

    fn start_browse(self: &Arc<Self>, inner: &mut Inner) {
        if self.stopping() || !self.ensure_mdns(inner) {
            return;
        }
        let Some(mdns) = inner.mdns.as_mut() else {
            return;
        };
        match mdns.browse() {
            Ok(Some(events)) => {
                let lan = self.clone();
                self.spawn(async move {
                    while let Ok(event) = events.recv_async().await {
                        lan.on_mdns(event);
                    }
                });
            }
            Ok(None) => {}
            Err(e) => self.mdns_failed(inner, e),
        }
    }

    fn on_mdns(&self, event: ServiceEvent) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        if !inner.browse {
            return;
        }
        let now = Instant::now();
        let changed = match event {
            ServiceEvent::ServiceResolved(service) => match mdns::Found::parse(&service) {
                Some(found) if found.id != self.me.id => {
                    let keep = |addr| mdns::keep(&self.on_link, addr);
                    inner.seen.found(found, &keep, now)
                }
                _ => false,
            },
            ServiceEvent::ServiceRemoved(_, fullname) => inner.seen.removed(&fullname),
            _ => false,
        };
        if changed {
            self.changed();
        }
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        let mut warned = false;
        loop {
            match listener.accept().await {
                Ok((stream, from)) => self.accepted(stream, from),
                Err(e) => {
                    if !std::mem::replace(&mut warned, true) {
                        self.push(LanSignal::Log(format!(
                            "⚠️ lan: a connection could not be accepted ({e})"
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn accepted(self: &Arc<Self>, stream: TcpStream, from: SocketAddr) {
        let ip = from.ip().to_canonical();
        if !self.on_link.accepts(ip) {
            return;
        }
        let text = ip.to_string();
        let reserved = (self.lock().book.trusted.iter())
            .any(|r| r.last_addr.as_deref() == Some(text.as_str()));
        let Some(slot) = self.slots.take(ip, reserved) else {
            return;
        };
        let lan = self.clone();
        let from = SocketAddr::new(ip, from.port());
        self.spawn(lan.inbound(stream, from, slot));
    }

    async fn inbound(self: Arc<Self>, stream: TcpStream, from: SocketAddr, slot: tunnel::Slot) {
        let Ok(est) = tunnel::accept(stream, &self.me).await else {
            return;
        };
        let mut guard = self.lock();
        let inner = &mut *guard;
        let peer = &est.peer;
        if self.stopping() || peer.id == self.me.id {
            return;
        }
        if inner.book.blocked.iter().any(|r| r.id == peer.id) {
            return;
        }
        let key = id::b64(&peer.key);
        let index = (inner.book.trusted.iter()).position(|r| r.id == peer.id && r.key == key);
        let ip = from.ip().to_string();
        let ip_blocked =
            (inner.book.blocked.iter()).any(|r| r.addr.as_deref() == Some(ip.as_str()));
        if (index.is_none() && ip_blocked) || inner.visibility == Visibility::Off {
            return;
        }
        if let Some(index) = index {
            inner.book.seen(index, from.ip(), store::now());
            let record = &mut inner.book.trusted[index];
            record.name = peer.name.clone();
            record.os = peer.os.clone();
            record.kind = peer.kind.clone();
            self.register(inner, est, from, false, true, None);
        } else if inner.visibility == Visibility::Open {
            self.register(inner, est, from, false, false, Some(slot));
        }
    }

    fn register(
        self: &Arc<Self>,
        inner: &mut Inner,
        est: Established<OwnedReadHalf, OwnedWriteHalf>,
        addr: SocketAddr,
        outbound: bool,
        admitted: bool,
        slot: Option<tunnel::Slot>,
    ) -> u64 {
        inner.serial += 1;
        let serial = inner.serial;
        let Established {
            reader,
            writer,
            h,
            peer,
            ..
        } = est;
        let (tx, rx) = mpsc::channel(tunnel::QUEUE);
        if !outbound {
            let _ = tx.try_send(self.me.hello(&inner.card, Role::Responder, &h));
            let _ = tx.try_send(LanFrame::Status { trusted: admitted });
        }
        self.spawn(tunnel::write_loop(writer, rx));
        let reader = self.spawn(self.clone().read(serial, reader));
        let older = inner.serials(|t| {
            t.peer.id == peer.id && t.outbound == outbound && (!outbound || t.asker.is_none())
        });
        inner.hellos.retain(|(known, _)| known.id != peer.id);
        inner.hellos.push((peer.clone(), store::now()));
        if inner.hellos.len() > HELLOS_MAX {
            inner.hellos.remove(0);
        }
        inner.tunnels.push(Tunnel {
            serial,
            peer,
            addr,
            outbound,
            admitted,
            h,
            registered: Instant::now(),
            tx,
            reader,
            slot,
            asker: None,
            answerer: None,
            warned: false,
        });
        for older in older {
            self.close(inner, older, false);
        }
        self.changed();
        serial
    }

    async fn read(self: Arc<Self>, serial: u64, mut reader: tunnel::Reader<OwnedReadHalf>) {
        while let Ok(frame) = reader.next().await {
            match self.on_frame(serial, frame) {
                Next::Go => {}
                Next::Stop => break,
                Next::Signal(signal) => {
                    if self.signals.send(*signal).await.is_err() {
                        break;
                    }
                }
            }
        }
        self.tunnel_gone(serial);
    }

    fn on_frame(self: &Arc<Self>, serial: u64, frame: LanFrame) -> Next {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let now = Instant::now();
        let Some(t) = inner.tunnel(serial) else {
            return Next::Stop;
        };
        let (outbound, admitted) = (t.outbound, t.admitted);
        let (id, key) = (t.peer.id.clone(), t.peer.key);
        let asking = t.asker.is_some();
        let answering = t.answerer.is_some();
        let challenged = t.answerer.as_ref().is_some_and(Answerer::challenged);
        match frame {
            LanFrame::Hello { .. } | LanFrame::Bye => Next::Stop,
            LanFrame::Status { trusted } if outbound => {
                if trusted {
                    return Next::Go;
                }
                self.revoked(inner, &id);
                match inner.tunnel_mut(serial) {
                    Some(t) => {
                        t.admitted = false;
                        if t.asker.is_some() {
                            Next::Go
                        } else {
                            Next::Stop
                        }
                    }
                    None => Next::Stop,
                }
            }
            LanFrame::Rtc { signal } if admitted => {
                Next::Signal(Box::new(LanSignal::Rtc { id, key, signal }))
            }
            LanFrame::PairRequest if !outbound => self.incoming_request(inner, serial, now),
            frame @ (LanFrame::PairChallenge { .. }
            | LanFrame::PairReveal { .. }
            | LanFrame::PairResult { .. }
            | LanFrame::PairRefused { .. })
                if outbound && asking =>
            {
                let reveal = matches!(frame, LanFrame::PairReveal { .. });
                let asker = inner.tunnel_mut(serial).and_then(|t| t.asker.as_mut());
                match asker.and_then(|asker| asker.on_frame(&frame, now)) {
                    Some(step) if reveal && step.done.is_some() => {
                        self.apply_asker(inner, serial, step);
                        self.close(inner, serial, false);
                        Next::Stop
                    }
                    Some(step) => {
                        self.apply_asker(inner, serial, step);
                        alive(inner, serial)
                    }
                    None => self.unfit(inner, serial),
                }
            }
            LanFrame::PairNonce { nonce } if !outbound && challenged => {
                self.reveal(inner, serial, &nonce, now)
            }
            LanFrame::PairConfirm if !outbound && answering => {
                let answerer = inner.tunnel_mut(serial).and_then(|t| t.answerer.as_mut());
                match answerer.and_then(Answerer::confirm) {
                    Some(step) => {
                        self.apply_answerer(inner, serial, step);
                        alive(inner, serial)
                    }
                    None => self.unfit(inner, serial),
                }
            }
            LanFrame::PairCancel if !outbound && answering => {
                let answerer = inner.tunnel_mut(serial).and_then(|t| t.answerer.take());
                if let Some(answerer) = answerer {
                    inner.pairing.cancel(answerer.request(), &id, now);
                    self.close_prompt(inner, answerer.request());
                }
                if admitted {
                    Next::Go
                } else {
                    Next::Stop
                }
            }
            _ => self.unfit(inner, serial),
        }
    }

    fn unfit(&self, inner: &mut Inner, serial: u64) -> Next {
        let Some(t) = inner.tunnel_mut(serial) else {
            return Next::Stop;
        };
        if t.admitted {
            return Next::Go;
        }
        if !std::mem::replace(&mut t.warned, true) {
            let id8 = id::id8(&t.peer.id).to_string();
            self.push(LanSignal::Log(format!(
                "lan: closed a tunnel from {id8}: unexpected frame"
            )));
        }
        self.close(inner, serial, false);
        Next::Stop
    }

    fn incoming_request(self: &Arc<Self>, inner: &mut Inner, serial: u64, now: Instant) -> Next {
        let Some(t) = inner.tunnel_mut(serial) else {
            return Next::Stop;
        };
        let (peer, ip, h, admitted) = (t.peer.clone(), t.addr.ip(), t.h, t.admitted);
        if peer.name.is_empty() {
            let refused = LanFrame::PairRefused {
                code: RefuseCode::NoName,
                retry_after_s: None,
            };
            self.send(inner, serial, refused);
            return self.close_unless(inner, serial, admitted);
        }
        let previous = t.answerer.take();
        if inner.outgoing.as_ref().is_some_and(|o| o.id == peer.id) {
            if let Some(t) = inner.tunnel_mut(serial) {
                t.answerer = previous;
            }
            let busy = LanFrame::PairRefused {
                code: RefuseCode::PairingBusy,
                retry_after_s: Some(pairing::BUSY_RETRY.as_secs()),
            };
            self.send(inner, serial, busy);
            return self.close_unless(inner, serial, admitted);
        }
        if let Some(previous) = previous {
            inner.pairing.cancel(previous.request(), &peer.id, now);
            self.close_prompt(inner, previous.request());
        }
        self.expire_pairing(inner, now);
        let ctx = Context {
            visible: inner.visibility == Visibility::Open,
            test_mode: self.test_mode,
            own: self.on_link.own(ip),
            blocked: inner.book.is_blocked(&peer.id, ip),
            known: inner.book.trusted(&peer.id).is_some() || inner.book.paired(&peer.id).is_some(),
            name_clash: inner.clash(&peer.id, &peer.name),
        };
        let expires_in = inner.pairing.expires();
        let request = match inner.pairing.request(peer.hello(), ip, ctx, now) {
            Ok(request) => (
                request.id.clone(),
                request.expires,
                request.replaces.clone(),
            ),
            Err(refused) => {
                let frame = LanFrame::PairRefused {
                    code: refused.code,
                    retry_after_s: refused.retry_after.map(|d| d.as_secs()),
                };
                self.send(inner, serial, frame);
                return self.close_unless(inner, serial, admitted);
            }
        };
        let (request, expires, replaces) = request;
        let (answerer, frame) = Answerer::challenge(h, request, expires_in, expires, now);
        if let Some(t) = inner.tunnel_mut(serial) {
            t.answerer = Some(answerer);
        }
        self.send(inner, serial, frame);
        if let Some(old) = replaces {
            if let Some(other) = inner.answering(&old).filter(|&other| other != serial) {
                let other_admitted = match inner.tunnel_mut(other) {
                    Some(t) => {
                        t.answerer = None;
                        t.admitted
                    }
                    None => true,
                };
                self.close_prompt(inner, &old);
                if !other_admitted {
                    self.close(inner, other, false);
                }
            }
        }
        alive(inner, serial)
    }

    fn reveal(self: &Arc<Self>, inner: &mut Inner, serial: u64, nonce: &str, now: Instant) -> Next {
        let nonce: Option<[u8; sas::NONCE_LEN]> =
            id::from_b64(nonce).and_then(|bytes| bytes.try_into().ok());
        let Some(t) = inner.tunnel_mut(serial) else {
            return Next::Stop;
        };
        let (peer, ip) = (t.peer.clone(), t.addr.ip());
        let Some(answerer) = t.answerer.as_mut() else {
            return Next::Stop;
        };
        let request = answerer.request().to_string();
        let Some(code) = nonce.and_then(|nonce| answerer.nonce(&nonce)) else {
            t.answerer = None;
            inner.pairing.cancel(&request, &peer.id, now);
            self.close(inner, serial, false);
            return Next::Stop;
        };
        let Some(revealed) = inner.pairing.revealed(&request, &peer.id, code.clone()) else {
            self.close(inner, serial, false);
            return Next::Stop;
        };
        let expires = revealed.expires;
        let prompt = PairPrompt {
            request,
            id: peer.id.clone(),
            fingerprint: id::fingerprint(&peer.id),
            name: peer.name,
            os: peer.os,
            kind: peer.kind,
            addr: ip,
            code,
            known: revealed.known,
            name_clash: revealed.name_clash,
            quiet: revealed.quiet,
            expires_in: expires.saturating_duration_since(now),
        };
        if !self.raise_prompt(inner, prompt, expires, now) {
            self.close(inner, serial, false);
            return Next::Stop;
        }
        let answerer = inner.tunnel_mut(serial).and_then(|t| t.answerer.as_mut());
        if let Some(frame) = answerer.and_then(Answerer::reveal) {
            self.send(inner, serial, frame);
        }
        alive(inner, serial)
    }

    fn raise_prompt(
        self: &Arc<Self>,
        inner: &mut Inner,
        prompt: PairPrompt,
        expires: Instant,
        now: Instant,
    ) -> bool {
        if self.stopping() {
            return false;
        }
        let (tx, rx) = oneshot::channel();
        let lan = self.clone();
        let request = prompt.request.clone();
        let reply = self.spawn(async move {
            let decision = rx.await.ok();
            lan.decide(&request, decision);
        });
        let Some(reply) = reply else {
            return false;
        };
        let raised = Raised {
            prompt: prompt.clone(),
            expires,
            reply,
        };
        inner.prompts.insert(prompt.request.clone(), raised);
        inner.pairing.shown(&prompt.request, now);
        self.push(LanSignal::Prompt(prompt, PairReply::new(tx)));
        self.changed();
        true
    }

    fn decide(self: &Arc<Self>, request: &str, decision: Option<PairDecision>) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let now = Instant::now();
        inner.prompts.remove(request);
        if inner.answering(request).is_none() {
            return;
        }
        self.expire_pairing(inner, now);
        let answer = match decision {
            Some(PairDecision::Allow { .. }) => Answer::Allow,
            Some(PairDecision::Deny) => Answer::Deny,
            Some(PairDecision::Block) => Answer::Block,
            None => Answer::NotShown,
        };
        let Some(answered) = inner.pairing.answer(request, answer, now) else {
            return;
        };
        let Some(serial) = inner.answering(request) else {
            return;
        };
        match answered {
            Answered::Allowed { .. } => {
                let remember = decision == Some(PairDecision::Allow { remember: true });
                let answerer = inner.tunnel_mut(serial).and_then(|t| t.answerer.as_mut());
                if let Some(step) = answerer.map(|answerer| answerer.allow(remember)) {
                    self.apply_answerer(inner, serial, step);
                }
            }
            Answered::Denied => {
                self.end_answer(inner, serial, WireOutcome::Denied);
                self.close_unadmitted(inner, serial);
            }
            Answered::Blocked { hello, addr } => {
                self.blocked_at_prompt(inner, serial, hello, addr, now);
            }
            Answered::NotShown => {
                inner.pairing.take_not_shown(request);
                self.end_answer(inner, serial, WireOutcome::NotShown);
                self.close_unadmitted(inner, serial);
            }
        }
        self.changed();
    }

    fn blocked_at_prompt(
        &self,
        inner: &mut Inner,
        serial: u64,
        hello: pairing::Hello,
        addr: IpAddr,
        now: Instant,
    ) {
        inner.book.block(BlockRecord {
            id: hello.id.clone(),
            name: hello.name.clone(),
            addr: Some(addr.to_string()),
            added: store::now(),
        });
        inner.book.revoke(&hello.id);
        inner.book.unpair(&hello.id);
        self.save(inner);
        self.end_answer(inner, serial, WireOutcome::Denied);
        let others = inner.serials(|t| {
            t.serial != serial
                && t.answerer.is_some()
                && (t.peer.id == hello.id || t.addr.ip() == addr)
        });
        for other in others {
            let Some(t) = inner.tunnel(other) else {
                continue;
            };
            let from = t.peer.id.clone();
            let Some(request) = t.answerer.as_ref().map(|a| a.request().to_string()) else {
                continue;
            };
            inner.pairing.cancel(&request, &from, now);
            self.end_answer(inner, other, WireOutcome::Denied);
            self.close_prompt(inner, &request);
            self.close_unadmitted(inner, other);
        }
        self.close_id(inner, &hello.id);
        self.push(LanSignal::Close { id: hello.id });
    }

    fn apply_answerer(self: &Arc<Self>, inner: &mut Inner, serial: u64, step: Step) {
        for frame in step.send {
            self.send(inner, serial, frame);
        }
        match step.done {
            Some(PairOutcome::Allowed) => self.finish_incoming(inner, serial),
            Some(_) => {
                if let Some(t) = inner.tunnel_mut(serial) {
                    t.answerer = None;
                }
            }
            None => {}
        }
    }

    fn end_answer(&self, inner: &mut Inner, serial: u64, outcome: WireOutcome) {
        let answerer = inner.tunnel_mut(serial).and_then(|t| t.answerer.take());
        let Some(mut answerer) = answerer else {
            return;
        };
        for frame in answerer.end(outcome).send {
            self.send(inner, serial, frame);
        }
    }

    fn end_incoming(&self, inner: &mut Inner, request: &str, outcome: WireOutcome) {
        let serial = inner.answering(request);
        if let Some(serial) = serial {
            self.end_answer(inner, serial, outcome);
        }
        self.close_prompt(inner, request);
        if let Some(serial) = serial {
            self.close_unadmitted(inner, serial);
        }
    }

    fn expire_pairing(&self, inner: &mut Inner, now: Instant) -> bool {
        let expired = inner.pairing.expire(now);
        for request in &expired {
            self.end_incoming(inner, request, WireOutcome::Expired);
        }
        !expired.is_empty()
    }

    fn finish_incoming(self: &Arc<Self>, inner: &mut Inner, serial: u64) {
        let Some(t) = inner.tunnel(serial) else {
            return;
        };
        let (peer, ip) = (t.peer.clone(), t.addr.ip());
        let remember = t.answerer.as_ref().is_some_and(Answerer::remember);
        let previous = inner.book.trusted(&peer.id).cloned();
        let evicted = inner.book.trust(TrustRecord {
            id: peer.id.clone(),
            name: peer.name.clone(),
            kind: peer.kind.clone(),
            os: peer.os.clone(),
            key: id::b64(&peer.key),
            added: previous.as_ref().map_or_else(store::now, |r| r.added),
            last_seen: store::now(),
            last_addr: Some(ip.to_string()),
            grants: previous.map_or_else(Grants::default, |r| r.grants),
            session_only: !remember,
        });
        self.save(inner);
        if let Some(evicted) = evicted {
            self.push(LanSignal::Log(format!(
                "⚠️ lan: 32 trusted devices at most; {} is no longer trusted",
                evicted.name
            )));
            self.close_id(inner, &evicted.id);
            self.push(LanSignal::Close { id: evicted.id });
        }
        self.push(LanSignal::Close {
            id: peer.id.clone(),
        });
        if let Some(t) = inner.tunnel_mut(serial) {
            t.admitted = true;
            t.slot = None;
            t.answerer = None;
        }
        self.reconcile(inner);
        self.changed();
    }

    fn start_asker(&self, inner: &mut Inner, serial: u64) {
        let Some(t) = inner.tunnel_mut(serial) else {
            return;
        };
        if t.peer.name.is_empty() {
            let (id, admitted) = (t.peer.id.clone(), t.admitted);
            inner.outgoing = None;
            self.event(LanEvent::PairDone {
                id,
                outcome: PairOutcome::Failed("the device has no name".to_string()),
            });
            self.close_unless(inner, serial, admitted);
            return;
        }
        let (asker, frame) = Asker::start(t.h, Instant::now());
        t.asker = Some(asker);
        self.send(inner, serial, frame);
    }

    fn apply_asker(&self, inner: &mut Inner, serial: u64, step: Step) {
        let Some(peer) = inner.tunnel(serial).map(|t| t.peer.clone()) else {
            return;
        };
        for frame in step.send {
            self.send(inner, serial, frame);
        }
        if let Some(code) = step.code {
            self.event(LanEvent::PairWaiting {
                id: peer.id.clone(),
                code,
            });
        }
        let Some(outcome) = step.done else {
            return;
        };
        if inner
            .outgoing
            .as_ref()
            .is_some_and(|o| o.serial == Some(serial))
        {
            inner.outgoing = None;
        }
        let Some(t) = inner.tunnel_mut(serial) else {
            return;
        };
        t.asker = None;
        if outcome != PairOutcome::Allowed {
            let admitted = t.admitted;
            self.event(LanEvent::PairDone {
                id: peer.id,
                outcome,
            });
            self.close_unless(inner, serial, admitted);
            return;
        }
        t.admitted = true;
        let addr = t.addr;
        let previous = inner.book.paired(&peer.id).cloned();
        inner.book.pair(PairedRecord {
            id: peer.id.clone(),
            name: peer.name.clone(),
            kind: peer.kind.clone(),
            os: peer.os.clone(),
            key: id::b64(&peer.key),
            last_addr: previous.as_ref().and_then(|r| r.last_addr.clone()),
            addrs: previous
                .as_ref()
                .map(|r| r.addrs.clone())
                .unwrap_or_default(),
            added: previous.map_or_else(store::now, |r| r.added),
        });
        inner.book.seen_at(&peer.id, addr);
        self.save(inner);
        self.event(LanEvent::PairDone {
            id: peer.id,
            outcome,
        });
        self.changed();
    }

    fn cancel_outgoing(&self, inner: &mut Inner, outcome: PairOutcome) {
        let Some(outgoing) = inner.outgoing.take() else {
            return;
        };
        match outgoing.serial {
            None => {
                if let Some(dial) = outgoing.dial {
                    dial.abort();
                }
            }
            Some(serial) => {
                self.send(inner, serial, LanFrame::PairCancel);
                let admitted = match inner.tunnel_mut(serial) {
                    Some(t) => {
                        t.asker = None;
                        t.admitted
                    }
                    None => true,
                };
                self.close_unless(inner, serial, admitted);
            }
        }
        self.event(LanEvent::PairDone {
            id: outgoing.id,
            outcome,
        });
    }

    async fn pair_dial(self: Arc<Self>, id: String, attempt: u64) {
        let (candidates, card) = {
            let inner = self.lock();
            (
                inner.candidates(&self.on_link, &id, Instant::now()),
                inner.card.clone(),
            )
        };
        let result = self.dial_any(&id, candidates, &card).await;
        let mut guard = self.lock();
        let inner = &mut *guard;
        if (inner.outgoing.as_ref()).is_none_or(|o| o.attempt != attempt) {
            return;
        }
        match result {
            Err(reason) => {
                inner.outgoing = None;
                self.event(LanEvent::PairDone {
                    id,
                    outcome: PairOutcome::Failed(reason),
                });
                self.changed();
            }
            Ok((addr, est)) => {
                let trusted = est.trusted;
                if !trusted {
                    self.revoked(inner, &id);
                }
                let serial = self.register(inner, est, addr, true, trusted, None);
                if let Some(outgoing) = inner.outgoing.as_mut() {
                    outgoing.serial = Some(serial);
                    outgoing.dial = None;
                }
                self.start_asker(inner, serial);
            }
        }
    }

    async fn open_dial(self: Arc<Self>, id: String, dial: u64) {
        let (candidates, card) = {
            let inner = self.lock();
            (
                inner.candidates(&self.on_link, &id, Instant::now()),
                inner.card.clone(),
            )
        };
        let result = self.dial_any(&id, candidates, &card).await;
        let mut guard = self.lock();
        let inner = &mut *guard;
        if inner.opening.get(&id).is_none_or(|o| o.dial != dial) {
            return;
        }
        let Some(opening) = inner.opening.remove(&id) else {
            return;
        };
        match result {
            Ok((addr, est)) if est.trusted => {
                let peer = est.peer.clone();
                let serial = self.register(inner, est, addr, true, true, None);
                inner.book.seen_at(&id, addr);
                if let Some(record) = inner.book.paired.iter_mut().find(|r| r.id == id) {
                    record.name = peer.name;
                    record.os = peer.os;
                    record.kind = peer.kind;
                }
                for signal in opening.queue {
                    self.send(inner, serial, LanFrame::Rtc { signal });
                }
                self.changed();
            }
            Ok(_) => {
                self.push(LanSignal::Unreachable {
                    id: id.clone(),
                    dial,
                    reason: "it no longer accepts this device".to_string(),
                });
                self.revoked(inner, &id);
            }
            Err(reason) => self.push(LanSignal::Unreachable { id, dial, reason }),
        }
    }

    async fn dial_any(
        &self,
        id: &str,
        candidates: Vec<SocketAddr>,
        card: &tunnel::Card,
    ) -> Result<Dialled, String> {
        let mut last: Option<TunnelError> = None;
        let mut warned = false;
        for addr in candidates {
            match tunnel::dial(addr, &self.me, card, id).await {
                Ok(est) => return Ok((addr, est)),
                Err(TunnelError::WrongId(other)) => {
                    {
                        let mut inner = self.lock();
                        inner.seen.bad(id, addr, Instant::now());
                    }
                    if !std::mem::replace(&mut warned, true) {
                        self.push(LanSignal::Log(format!(
                            "⚠️ lan: {addr} answered as another device"
                        )));
                    }
                    last = Some(TunnelError::WrongId(other));
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or_else(
            || "no address known for this device".to_string(),
            |e| e.to_string(),
        ))
    }

    fn revoked(&self, inner: &mut Inner, id: &str) {
        if inner.book.unpair(id).is_some() {
            self.save(inner);
            self.event(LanEvent::Unpaired { id: id.to_string() });
            self.push(LanSignal::Close { id: id.to_string() });
            self.changed();
        }
    }

    fn drop_device(self: &Arc<Self>, inner: &mut Inner, id: &str) {
        if inner.outgoing.as_ref().is_some_and(|o| o.id == id) {
            self.cancel_outgoing(inner, PairOutcome::Cancelled);
        }
        self.close_id(inner, id);
        if let Some(opening) = inner.opening.remove(id) {
            opening.task.abort();
        }
        self.push(LanSignal::Close { id: id.to_string() });
        self.reconcile(inner);
        self.changed();
    }

    fn tick(&self, now: Instant) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let mut any = self.expire_pairing(inner, now);
        for serial in inner.serials(|t| deadline(t).is_some_and(|at| at <= now)) {
            let Some(t) = inner.tunnel(serial) else {
                continue;
            };
            let due = match (&t.asker, &t.answerer) {
                (Some(asker), _) => Due::Asker(Step {
                    send: if asker.challenged() || asker.comparing() {
                        vec![LanFrame::PairCancel]
                    } else {
                        Vec::new()
                    },
                    code: None,
                    done: Some(asker.timed_out()),
                }),
                (None, Some(answerer)) if answerer.challenged() => Due::Challenged {
                    request: answerer.request().to_string(),
                    from: t.peer.id.clone(),
                },
                (None, Some(answerer)) if answerer.undecided() => {
                    Due::Undecided(answerer.request().to_string())
                }
                (None, Some(_)) => Due::Unconfirmed,
                (None, None) => Due::Stranger,
            };
            any = true;
            match due {
                Due::Asker(step) => self.apply_asker(inner, serial, step),
                Due::Challenged { request, from } => {
                    if let Some(t) = inner.tunnel_mut(serial) {
                        t.answerer = None;
                    }
                    inner.pairing.cancel(&request, &from, now);
                    self.close_unadmitted(inner, serial);
                }
                Due::Undecided(request) => self.end_incoming(inner, &request, WireOutcome::Expired),
                Due::Unconfirmed => {
                    self.end_answer(inner, serial, WireOutcome::Expired);
                    self.close_unadmitted(inner, serial);
                }
                Due::Stranger => self.close(inner, serial, false),
            }
        }
        if let Some(mdns) = inner.mdns.as_mut() {
            mdns.retire_due(now);
        }
        if any {
            self.changed();
        }
    }

    fn send(&self, inner: &mut Inner, serial: u64, frame: LanFrame) {
        let Some(t) = inner.tunnel(serial) else {
            return;
        };
        if let Err(TrySendError::Full(_)) = t.tx.try_send(frame) {
            self.close(inner, serial, false);
        }
    }

    fn close_unadmitted(&self, inner: &mut Inner, serial: u64) {
        let admitted = inner.tunnel(serial).is_none_or(|t| t.admitted);
        self.close_unless(inner, serial, admitted);
    }

    fn close_unless(&self, inner: &mut Inner, serial: u64, admitted: bool) -> Next {
        if admitted {
            return alive(inner, serial);
        }
        self.close(inner, serial, false);
        Next::Stop
    }

    fn close_id(&self, inner: &mut Inner, id: &str) {
        for serial in inner.serials(|t| t.peer.id == id) {
            let revoke = inner.tunnel(serial).is_some_and(|t| !t.outbound);
            self.close(inner, serial, revoke);
        }
    }

    fn close(&self, inner: &mut Inner, serial: u64, revoke: bool) {
        let Some(index) = inner.tunnels.iter().position(|t| t.serial == serial) else {
            return;
        };
        let t = inner.tunnels.remove(index);
        if revoke {
            let _ = t.tx.try_send(LanFrame::Status { trusted: false });
        }
        let _ = t.tx.try_send(LanFrame::Bye);
        if let Some(reader) = &t.reader {
            reader.abort();
        }
        self.cleanup(inner, t);
    }

    fn tunnel_gone(&self, serial: u64) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        if let Some(index) = inner.tunnels.iter().position(|t| t.serial == serial) {
            let t = inner.tunnels.remove(index);
            self.cleanup(inner, t);
        }
    }

    fn cleanup(&self, inner: &mut Inner, t: Tunnel) {
        let now = Instant::now();
        let mut notable = t.admitted;
        if let Some(answerer) = &t.answerer {
            inner.pairing.cancel(answerer.request(), &t.peer.id, now);
            self.close_prompt(inner, answerer.request());
            notable = true;
        }
        if t.asker.is_some() {
            notable = true;
            if inner
                .outgoing
                .as_ref()
                .is_some_and(|o| o.serial == Some(t.serial))
            {
                inner.outgoing = None;
                self.event(LanEvent::PairDone {
                    id: t.peer.id.clone(),
                    outcome: PairOutcome::Failed("the connection was lost".to_string()),
                });
            }
        }
        drop(t.slot);
        if notable {
            self.changed();
        }
    }

    fn close_prompt(&self, inner: &mut Inner, request: &str) {
        if let Some(raised) = inner.prompts.remove(request) {
            raised.reply.abort();
            self.event(LanEvent::PromptClosed {
                request: request.to_string(),
            });
        }
    }
}

fn alive(inner: &Inner, serial: u64) -> Next {
    if inner.tunnel(serial).is_some() {
        Next::Go
    } else {
        Next::Stop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Memory(Mutex<Option<String>>);

    impl TrustStore for Memory {
        fn load(&self) -> io::Result<Option<String>> {
            Ok(self.0.lock().unwrap().clone())
        }

        fn save(&self, doc: &str) -> io::Result<()> {
            *self.0.lock().unwrap() = Some(doc.to_string());
            Ok(())
        }
    }

    fn inner() -> Inner {
        Inner {
            card: tunnel::Card {
                name: "Me".into(),
                os: "linux".into(),
                kind: "desktop".into(),
            },
            config_port: 0,
            visibility: Visibility::Open,
            browse: false,
            unreadable: false,
            book: Book::open(Arc::new(Memory::default()), &|_| {}).unwrap(),
            pairing: Pairing::default(),
            seen: mdns::Seen::default(),
            mdns: None,
            mdns_failed: false,
            listening: None,
            last_port: None,
            tunnels: Vec::new(),
            serial: 0,
            dial_seq: 0,
            attempt: 0,
            opening: HashMap::new(),
            outgoing: None,
            prompts: HashMap::new(),
            hellos: Vec::new(),
            sessions: HashMap::new(),
            account: Vec::new(),
        }
    }

    fn peer(seed: u8, name: &str) -> tunnel::Peer {
        let key = [seed; 32];
        tunnel::Peer {
            id: id::id_of_bytes(&key),
            key,
            name: name.into(),
            os: "linux".into(),
            kind: "desktop".into(),
        }
    }

    fn tunnel(serial: u64, peer: &tunnel::Peer, admitted: bool) -> Tunnel {
        let (tx, _) = mpsc::channel(1);
        Tunnel {
            serial,
            peer: peer.clone(),
            addr: "127.0.0.1:1".parse().unwrap(),
            outbound: true,
            admitted,
            h: [0; 32],
            registered: Instant::now(),
            tx,
            reader: None,
            slot: None,
            asker: None,
            answerer: None,
            warned: false,
        }
    }

    fn trusted(peer: &tunnel::Peer, last_seen: u64) -> TrustRecord {
        TrustRecord {
            id: peer.id.clone(),
            name: peer.name.clone(),
            kind: peer.kind.clone(),
            os: peer.os.clone(),
            key: id::b64(&peer.key),
            added: 1,
            last_seen,
            last_addr: None,
            grants: Grants::default(),
            session_only: false,
        }
    }

    fn paired(peer: &tunnel::Peer, last_addr: Option<&str>, addrs: &[&str]) -> PairedRecord {
        PairedRecord {
            id: peer.id.clone(),
            name: peer.name.clone(),
            kind: peer.kind.clone(),
            os: peer.os.clone(),
            key: id::b64(&peer.key),
            last_addr: last_addr.map(str::to_string),
            addrs: addrs.iter().map(|a| a.to_string()).collect(),
            added: 2,
        }
    }

    fn found(fullname: &str, id: &str, name: &str, addr: &str) -> mdns::Found {
        mdns::Found {
            fullname: fullname.into(),
            id: id.into(),
            name: name.into(),
            os: "android".into(),
            kind: "phone".into(),
            addrs: vec![addr.parse().unwrap()],
        }
    }

    fn on_link() -> net::OnLink {
        let wlan = net::Iface {
            name: "wlan0".into(),
            ip: "192.168.1.10".parse().unwrap(),
            prefixlen: 24,
            up: true,
            p2p: false,
        };
        net::OnLink::with_interfaces(false, vec![wlan])
    }

    fn addrs(list: &[&str]) -> Vec<SocketAddr> {
        list.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn listener_and_advert_follow_visibility() {
        assert_eq!(wanted(Visibility::Open, false, false), (true, true));
        assert_eq!(wanted(Visibility::Open, true, false), (true, true));
        assert_eq!(
            wanted(Visibility::TrustedOnly, false, false),
            (false, false)
        );
        assert_eq!(wanted(Visibility::TrustedOnly, true, false), (true, false));
        assert_eq!(wanted(Visibility::Off, false, false), (false, false));
        assert_eq!(wanted(Visibility::Off, true, false), (false, false));
        for visibility in [Visibility::Open, Visibility::TrustedOnly, Visibility::Off] {
            for any_trusted in [false, true] {
                assert_eq!(wanted(visibility, any_trusted, true), (false, false));
            }
        }
    }

    #[test]
    fn name_clash_counts_other_ids_only() {
        let mut inner = inner();
        let room = peer(1, "Living Room");
        let other = peer(2, "Other").id;
        inner.hellos.push((room.clone(), 0));
        assert!(!inner.clash(&room.id, "Living Room"));
        assert!(inner.clash(&other, "living\u{200b}room"));
        assert!(inner.clash(&other, "LIVING ROOM\u{feff}"));
        assert!(inner.clash(&other, "Living\u{E0041}\u{180E} Room"));
        assert!(!inner.clash(&other, "Bedroom"));
        assert!(!inner.clash(&other, "\u{200b}"));
        assert_eq!(skeleton(" Ж\u{00AD}Ж\tx "), "жжx");

        let node = |key: [u8; 32], name: &str| NodeInfo {
            id: "account".into(),
            name: name.into(),
            os: "linux".into(),
            version: "1".into(),
            app_type: "app".into(),
            build_type: "release".into(),
            public_key: id::b64(&key),
            resources: Vec::new(),
            is_online: true,
            last_used: 0,
            is_temporary: false,
        };
        let mut inner = self::inner();
        let mut broken = node([4; 32], "Broken");
        broken.public_key = "not a key".into();
        inner.account = account_names(&[node([1; 32], "Office"), node([3; 32], "Desk"), broken]);
        assert_eq!(inner.account.len(), 2);
        assert!(!inner.clash(&peer(1, "Office").id, "Office"));
        assert!(inner.clash(&other, "office"));
        assert!(inner.clash(&other, "D e s k"));
    }

    #[test]
    fn candidates_put_stored_first_and_skip_bad() {
        let (on_link, now) = (on_link(), Instant::now());
        let mut inner = inner();
        let b = peer(2, "B");
        let stored = paired(
            &b,
            Some("192.168.1.30:8308"),
            &["192.168.1.31:8308", "10.9.9.9:8308"],
        );
        inner.book.pair(stored);
        for addr in [
            "192.168.1.40:8308",
            "192.168.1.30:8308",
            "192.168.1.10:8309",
        ] {
            inner.seen.inject(&b.id, addr.parse().unwrap(), now);
        }
        assert_eq!(
            inner.candidates(&on_link, &b.id, now),
            addrs(&[
                "192.168.1.30:8308",
                "192.168.1.31:8308",
                "192.168.1.40:8308",
                "192.168.1.10:8309"
            ])
        );
        inner
            .seen
            .bad(&b.id, "192.168.1.31:8308".parse().unwrap(), now);
        assert_eq!(
            inner.candidates(&on_link, &b.id, now),
            addrs(&[
                "192.168.1.30:8308",
                "192.168.1.40:8308",
                "192.168.1.10:8309"
            ])
        );

        let c = peer(3, "C");
        let stored = paired(
            &c,
            Some("192.168.1.50:1"),
            &["192.168.1.51:1", "192.168.1.52:1", "192.168.1.53:1"],
        );
        inner.book.pair(stored);
        for last in 60..64 {
            let addr = SocketAddr::from(([192, 168, 1, last], 1));
            inner.seen.inject(&c.id, addr, now);
        }
        assert_eq!(
            inner.candidates(&on_link, &c.id, now),
            addrs(&[
                "192.168.1.50:1",
                "192.168.1.51:1",
                "192.168.1.52:1",
                "192.168.1.53:1",
                "192.168.1.63:1",
                "192.168.1.62:1"
            ])
        );
        assert!(inner.candidates(&on_link, &peer(4, "D").id, now).is_empty());
    }

    #[test]
    fn a_wrong_id_keeps_the_stored_address() {
        let (on_link, now) = (on_link(), Instant::now());
        let mut inner = inner();
        let b = peer(2, "B");
        inner.book.pair(paired(&b, Some("192.168.1.30:8308"), &[]));
        let addr: SocketAddr = "192.168.1.30:8308".parse().unwrap();
        inner.seen.bad(&b.id, addr, now);
        assert_eq!(inner.book.paired(&b.id).unwrap().addresses(), [addr]);
        assert!(inner.candidates(&on_link, &b.id, now).is_empty());
        let later = now + Duration::from_secs(600);
        assert_eq!(inner.candidates(&on_link, &b.id, later), [addr]);
    }

    #[test]
    fn a_newer_book_is_refused() {
        let stored = |doc: &str| Checked(Arc::new(Memory(Mutex::new(Some(doc.to_string())))));
        assert!(stored(r#"{"v":2,"trusted":[]}"#).load().is_err());
        assert!(stored(r#"{"v":1.5}"#).load().is_err());
        let current = r#"{"v":1,"trusted":[]}"#;
        assert_eq!(stored(current).load().unwrap().as_deref(), Some(current));
        assert_eq!(
            stored("not json").load().unwrap().as_deref(),
            Some("not json")
        );
        assert!(Checked(Arc::new(Memory::default()))
            .load()
            .unwrap()
            .is_none());
        let newer = Arc::new(stored(r#"{"v":2,"paired":"changed"}"#));
        assert!(Book::open(newer, &|_| {}).is_err());
        let unwritable = Unwritable("read failed".into());
        assert!(unwritable.load().unwrap().is_none());
        assert_eq!(
            unwritable.save("{}").unwrap_err().to_string(),
            "read failed"
        );
    }

    #[test]
    fn devices_merge_records_seen_tunnels_and_sessions() {
        let now = Instant::now();
        let mut inner = inner();
        let me = peer(9, "Me");
        let zeta = peer(1, "zeta");
        let alpha = peer(2, "Alpha");
        let beta = peer(3, "beta");
        let gamma = peer(4, "Gamma");
        let blocked = peer(5, "Blocked");
        let stranger = peer(6, "Stranger");
        let twin = peer(7, "ALPHA");
        inner.book.trust(trusted(&zeta, 50));
        inner.hellos.push((peer(1, "Zeta Hello"), 60));
        inner.book.pair(paired(&alpha, Some("192.168.1.2:1"), &[]));
        inner.sessions.insert(
            alpha.id.clone(),
            vec![SharedResource {
                id: format!("fs-{}", alpha.id),
                name: "Files".into(),
                resource_type: nodeinnet_p2p::ResourceType::Filesystem,
                config: None,
                is_active: true,
                session_token: None,
            }],
        );
        let keep = |_| true;
        let seen = [
            found("alpha", &alpha.id, "Spoofed", "192.168.1.2:1"),
            found("beta", &beta.id, "beta", "192.168.1.3:1"),
            found("twin", &twin.id, "ALPHA", "192.168.1.7:1"),
            found("me", &me.id, "Me", "192.168.1.9:1"),
            found("blocked", &blocked.id, "Blocked", "192.168.1.5:1"),
        ];
        for found in seen {
            inner.seen.found(found, &keep, now);
        }
        inner.tunnels.push(tunnel(1, &gamma, true));
        inner.hellos.push((gamma.clone(), 70));
        inner.tunnels.push(tunnel(2, &stranger, false));
        inner.book.block(BlockRecord {
            id: blocked.id.clone(),
            name: "Blocked".into(),
            addr: None,
            added: 40,
        });

        let devices = inner.devices(&me.id, now);
        let names: Vec<&str> = devices.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["Alpha", "Zeta Hello", "ALPHA", "beta", "Gamma"]);
        let by_name = |name: &str| devices.iter().find(|d| d.name == name).unwrap();

        let alpha = by_name("Alpha");
        assert!(alpha.opened_from_here && alpha.may_open_me.is_none());
        assert!(alpha.name_verified && alpha.name_clash && alpha.online);
        assert_eq!(alpha.resources.len(), 1);
        assert_eq!(alpha.fingerprint, id::fingerprint(&alpha.id));

        let zeta = by_name("Zeta Hello");
        assert_eq!(zeta.may_open_me, Some(Grants::default()));
        assert!(!zeta.opened_from_here && zeta.name_verified && !zeta.online);
        assert_eq!(zeta.last_seen, 60);

        let twin = by_name("ALPHA");
        assert!(!twin.name_verified && twin.name_clash && twin.online);
        assert_eq!((twin.os.as_str(), twin.kind.as_str()), ("android", "phone"));

        let beta = by_name("beta");
        assert!(!beta.name_verified && !beta.name_clash && beta.online);
        assert!(beta.last_seen >= store::now() - 1);

        let gamma = by_name("Gamma");
        assert!(gamma.name_verified && gamma.online && gamma.may_open_me.is_none());
        assert_eq!(gamma.last_seen, 70);

        let state = inner.state(&me.id, now);
        assert_eq!(state.devices.len(), 5);
        assert_eq!(state.blocked.len(), 1);
        assert_eq!(state.blocked[0].id, blocked.id);
        assert_eq!(state.blocked[0].last_seen, 40);
        assert_eq!(
            (state.port, state.visibility, state.paused),
            (0, Visibility::Open, false)
        );
        assert_eq!(inner.name_of(&blocked.id), "Blocked");
        assert_eq!(inner.name_of(&peer(8, "x").id), id::id8(&peer(8, "x").id));
    }
}
