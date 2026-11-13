use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use nodeinnet_p2p::crypto::generate_ed25519_keypair;
use nodeinnet_p2p::RtcSignal;
use p2p_node::lan::{
    id, Grants, Lan, LanConfig, LanEvent, LanSignal, LanState, PairDecision, PairOutcome,
    PairPrompt, PairReply, RefuseCode, TrustStore, Visibility,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const WAIT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Memory {
    doc: Mutex<Option<String>>,
    unreadable: bool,
    refuses: bool,
}

impl Memory {
    fn holding(doc: &str) -> Memory {
        Memory {
            doc: Mutex::new(Some(doc.to_string())),
            ..Memory::default()
        }
    }

    fn text(&self) -> Option<String> {
        self.doc.lock().unwrap().clone()
    }

    fn book(&self) -> Value {
        serde_json::from_str(&self.text().expect("a saved book")).unwrap()
    }
}

impl TrustStore for Memory {
    fn load(&self) -> io::Result<Option<String>> {
        if self.unreadable {
            return Err(io::Error::other("the disk is gone"));
        }
        Ok(self.text())
    }

    fn save(&self, doc: &str) -> io::Result<()> {
        if self.refuses {
            return Err(io::Error::other("read-only"));
        }
        *self.doc.lock().unwrap() = Some(doc.to_string());
        Ok(())
    }
}

fn listed(book: &Value, list: &str, id: &str) -> bool {
    (book[list].as_array().into_iter().flatten()).any(|record| record["id"] == id)
}

struct Device {
    lan: Arc<Lan>,
    heard: Arc<Mutex<VecDeque<LanSignal>>>,
    store: Arc<Memory>,
    key: String,
    drain: JoinHandle<()>,
}

impl Device {
    async fn start(name: &str, visibility: Visibility) -> Device {
        let key = generate_ed25519_keypair().0;
        Device::with(name, visibility, Arc::new(Memory::default()), key, false).await
    }

    async fn with(
        name: &str,
        visibility: Visibility,
        store: Arc<Memory>,
        key: String,
        browse: bool,
    ) -> Device {
        let (signals, mut rx) = mpsc::channel(64);
        let heard = Arc::new(Mutex::new(VecDeque::new()));
        let sink = heard.clone();
        let drain = tokio::spawn(async move {
            while let Some(signal) = rx.recv().await {
                sink.lock().unwrap().push_back(signal);
            }
        });
        let config = LanConfig {
            name: name.to_string(),
            os: "linux".to_string(),
            kind: "test".to_string(),
            visibility,
            browse,
            port: 0,
            resources: vec![],
            trust: store.clone(),
            test_mode: true,
        };
        let lan = Lan::start(config, &key, signals).await.expect("lan");
        Device {
            lan,
            heard,
            store,
            key,
            drain,
        }
    }

    async fn restart(self) -> Device {
        let (store, key) = (self.store.clone(), self.key.clone());
        let visibility = self.lan.visibility();
        self.stop().await;
        Device::with("restarted", visibility, store, key, false).await
    }

    async fn stop(self) {
        self.lan.stop().await;
        self.drain.abort();
    }

    fn id(&self) -> String {
        self.lan.id().to_string()
    }

    fn addr(&self) -> SocketAddr {
        let port = self.lan.port().expect("a listener");
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn knows_address_of(&self, other: &Device) {
        self.lan.add_address(&other.id(), other.addr());
    }

    fn heard(&self, pick: impl Fn(&LanSignal) -> bool) -> bool {
        self.heard.lock().unwrap().iter().any(pick)
    }

    async fn take_within(
        &self,
        wait: Duration,
        pick: impl Fn(&LanSignal) -> bool,
    ) -> Option<LanSignal> {
        let deadline = Instant::now() + wait;
        loop {
            {
                let mut heard = self.heard.lock().unwrap();
                if let Some(index) = heard.iter().position(&pick) {
                    return heard.remove(index);
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn take(&self, what: &str, pick: impl Fn(&LanSignal) -> bool) -> LanSignal {
        match self.take_within(WAIT, pick).await {
            Some(signal) => signal,
            None => panic!(
                "{what} not heard in {WAIT:?}; heard {:?}",
                self.heard.lock().unwrap()
            ),
        }
    }

    async fn prompt(&self) -> (PairPrompt, PairReply) {
        match self
            .take("a prompt", |s| matches!(s, LanSignal::Prompt(..)))
            .await
        {
            LanSignal::Prompt(prompt, reply) => (prompt, reply),
            _ => unreachable!(),
        }
    }

    async fn waiting(&self, id: &str) -> String {
        let pick = |s: &LanSignal| matches!(s, LanSignal::Event(LanEvent::PairWaiting { id: of, .. }) if of == id);
        match self.take("PairWaiting", pick).await {
            LanSignal::Event(LanEvent::PairWaiting { code, .. }) => code,
            _ => unreachable!(),
        }
    }

    async fn done(&self, id: &str) -> PairOutcome {
        let pick = |s: &LanSignal| matches!(s, LanSignal::Event(LanEvent::PairDone { id: of, .. }) if of == id);
        match self.take("PairDone", pick).await {
            LanSignal::Event(LanEvent::PairDone { outcome, .. }) => outcome,
            _ => unreachable!(),
        }
    }

    async fn closed(&self, id: &str) {
        let pick = |s: &LanSignal| matches!(s, LanSignal::Close { id: of } if of == id);
        self.take("Close", pick).await;
    }

    async fn unpaired(&self, id: &str) {
        let pick = |s: &LanSignal| matches!(s, LanSignal::Event(LanEvent::Unpaired { id: of }) if of == id);
        self.take("Unpaired", pick).await;
    }

    async fn rtc(&self, id: &str) -> ([u8; 32], RtcSignal) {
        let pick = |s: &LanSignal| matches!(s, LanSignal::Rtc { id: of, .. } if of == id);
        match self.take("Rtc", pick).await {
            LanSignal::Rtc { key, signal, .. } => (key, signal),
            _ => unreachable!(),
        }
    }

    async fn unreachable(&self, id: &str) -> (u64, String) {
        let pick = |s: &LanSignal| matches!(s, LanSignal::Unreachable { id: of, .. } if of == id);
        match self.take("Unreachable", pick).await {
            LanSignal::Unreachable { dial, reason, .. } => (dial, reason),
            _ => unreachable!(),
        }
    }

    async fn not_saved(&self) -> String {
        let pick = |s: &LanSignal| matches!(s, LanSignal::Event(LanEvent::NotSaved(_)));
        match self.take("NotSaved", pick).await {
            LanSignal::Event(LanEvent::NotSaved(why)) => why,
            _ => unreachable!(),
        }
    }

    async fn state_where(&self, what: &str, pick: impl Fn(&LanState) -> bool) -> LanState {
        let pick =
            |s: &LanSignal| matches!(s, LanSignal::Event(LanEvent::State(state)) if pick(state));
        match self.take(what, pick).await {
            LanSignal::Event(LanEvent::State(state)) => state,
            _ => unreachable!(),
        }
    }

    async fn until(&self, what: &str, done: impl Fn(&Lan) -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done(&self.lan) {
            assert!(Instant::now() < deadline, "{what} not reached in {WAIT:?}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn offer(sdp: &str, ice_restart: bool) -> RtcSignal {
    RtcSignal::Offer {
        sdp: sdp.to_string(),
        ice_restart,
    }
}

fn candidate() -> RtcSignal {
    RtcSignal::IceCandidate {
        candidate: "candidate:1 1 udp 1 192.168.1.2 9 typ host".to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
    }
}

fn other_code(code: &str) -> &'static str {
    if code == "000 000" {
        "000 001"
    } else {
        "000 000"
    }
}

async fn ask(a: &Device, b: &Device) -> (PairPrompt, PairReply, String) {
    a.knows_address_of(b);
    a.lan.pair(&b.id());
    let (prompt, reply) = b.prompt().await;
    let code = a.waiting(&b.id()).await;
    assert_eq!(prompt.code, code);
    (prompt, reply, code)
}

async fn pair_with(a: &Device, b: &Device, remember: bool) -> PairPrompt {
    let (prompt, reply, code) = ask(a, b).await;
    reply.answer(PairDecision::Allow { remember });
    a.lan.confirm_pair(&b.id(), &code);
    assert_eq!(a.done(&b.id()).await, PairOutcome::Allowed);
    b.closed(&a.id()).await;
    prompt
}

async fn pair(a: &Device, b: &Device) -> PairPrompt {
    pair_with(a, b, true).await
}

async fn fresh_tunnel(a: &Device, b: &Device) -> u64 {
    a.lan.session(&b.id(), None);
    a.until("the old tunnel gone", |lan| {
        !lan.send_rtc(&b.id(), candidate())
    })
    .await;
    let opened = a.lan.open(&b.id()).expect("a paired device");
    assert_ne!(opened.dial, 0);
    a.until("the new tunnel", |lan| !lan.dialing(&b.id())).await;
    opened.dial
}

struct RawPeer {
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    cipher: snow::StatelessTransportState,
    h: [u8; 32],
    sent: u64,
    read: u64,
}

async fn write_raw(wr: &mut OwnedWriteHalf, msg: &[u8]) {
    let mut out = (msg.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    wr.write_all(&out).await.unwrap();
}

async fn read_raw(rd: &mut OwnedReadHalf) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    rd.read_exact(&mut len).await?;
    let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
    rd.read_exact(&mut msg).await?;
    Ok(msg)
}

fn hello(signing: &SigningKey, role: u8, h: &[u8; 32], name: &str) -> Value {
    let mut signed = b"nin-lan/1 hello".to_vec();
    signed.push(role);
    signed.extend_from_slice(h);
    json!({
        "t": "hello",
        "v": 1,
        "key": STANDARD_NO_PAD.encode(signing.verifying_key().to_bytes()),
        "name": name,
        "os": "linux",
        "kind": "test",
        "sig": STANDARD_NO_PAD.encode(signing.sign(&signed).to_bytes()),
    })
}

fn commitment(h: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
    let hash = Sha256::new()
        .chain_update(b"nin-lan/1 commit")
        .chain_update(h)
        .chain_update(nonce)
        .finalize();
    hash.to_vec()
}

#[cfg(target_os = "linux")]
fn code_of(h: &[u8; 32], initiator: &[u8], responder: &[u8]) -> String {
    let hash = Sha256::new()
        .chain_update(b"nin-lan/1 sas")
        .chain_update(h)
        .chain_update(initiator)
        .chain_update(responder)
        .finalize();
    let code = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 1_000_000;
    format!("{:03} {:03}", code / 1000, code % 1000)
}

#[cfg(target_os = "linux")]
fn bytes_of(value: &Value) -> Vec<u8> {
    id::from_b64(value.as_str().expect("base64")).expect("base64")
}

impl RawPeer {
    async fn connect(addr: SocketAddr) -> RawPeer {
        RawPeer::named(addr, "raw").await
    }

    async fn named(addr: SocketAddr, name: &str) -> RawPeer {
        RawPeer::over(TcpStream::connect(addr).await.unwrap(), name).await
    }

    #[cfg(target_os = "linux")]
    async fn from(source: IpAddr, addr: SocketAddr) -> RawPeer {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::new(source, 0)).unwrap();
        RawPeer::over(socket.connect(addr).await.unwrap(), "raw").await
    }

    async fn over(stream: TcpStream, name: &str) -> RawPeer {
        let (mut rd, mut wr) = stream.into_split();
        let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let keypair = snow::Builder::new(params.clone())
            .generate_keypair()
            .unwrap();
        let mut hs = snow::Builder::new(params)
            .prologue(b"nodeinnet-lan/1")
            .local_private_key(&keypair.private)
            .build_initiator()
            .unwrap();
        let (mut out, mut payload) = ([0u8; 1024], [0u8; 1024]);
        let n = hs.write_message(&[], &mut out).unwrap();
        write_raw(&mut wr, &out[..n]).await;
        let msg = read_raw(&mut rd).await.unwrap();
        hs.read_message(&msg, &mut payload).unwrap();
        let n = hs.write_message(&[], &mut out).unwrap();
        write_raw(&mut wr, &out[..n]).await;
        let h: [u8; 32] = hs.get_handshake_hash().try_into().unwrap();
        let cipher = hs.into_stateless_transport_mode().unwrap();
        let mut peer = RawPeer {
            rd,
            wr,
            cipher,
            h,
            sent: 0,
            read: 0,
        };
        let signing = SigningKey::from_bytes(&rand::random());
        peer.send(hello(&signing, b'I', &h, name)).await;
        assert_eq!(peer.recv().await.expect("the hello")["t"], "hello");
        let status = peer.recv().await.expect("a status");
        assert_eq!(status, json!({"t": "status", "trusted": false}));
        peer
    }

    async fn answer(stream: TcpStream, signing: &SigningKey, name: &str, trusted: bool) -> RawPeer {
        let (mut rd, mut wr) = stream.into_split();
        let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let keypair = snow::Builder::new(params.clone())
            .generate_keypair()
            .unwrap();
        let mut hs = snow::Builder::new(params)
            .prologue(b"nodeinnet-lan/1")
            .local_private_key(&keypair.private)
            .build_responder()
            .unwrap();
        let (mut out, mut payload) = ([0u8; 1024], [0u8; 1024]);
        let msg = read_raw(&mut rd).await.unwrap();
        hs.read_message(&msg, &mut payload).unwrap();
        let n = hs.write_message(&[], &mut out).unwrap();
        write_raw(&mut wr, &out[..n]).await;
        let msg = read_raw(&mut rd).await.unwrap();
        hs.read_message(&msg, &mut payload).unwrap();
        let h: [u8; 32] = hs.get_handshake_hash().try_into().unwrap();
        let cipher = hs.into_stateless_transport_mode().unwrap();
        let mut peer = RawPeer {
            rd,
            wr,
            cipher,
            h,
            sent: 0,
            read: 0,
        };
        assert_eq!(peer.recv().await.expect("the hello")["t"], "hello");
        peer.send(hello(signing, b'R', &h, name)).await;
        peer.send(json!({"t": "status", "trusted": trusted})).await;
        peer
    }

    async fn send(&mut self, frame: Value) {
        let json = serde_json::to_vec(&frame).unwrap();
        let mut out = vec![0u8; json.len() + 16];
        let n = self
            .cipher
            .write_message(self.sent, &json, &mut out)
            .unwrap();
        self.sent += 1;
        write_raw(&mut self.wr, &out[..n]).await;
    }

    async fn recv(&mut self) -> Option<Value> {
        let msg = read_raw(&mut self.rd).await.ok()?;
        let mut out = vec![0u8; msg.len()];
        let n = self.cipher.read_message(self.read, &msg, &mut out).ok()?;
        self.read += 1;
        serde_json::from_slice(&out[..n]).ok()
    }

    async fn closed_within(&mut self, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, self.recv()).await {
                Ok(None) => return true,
                Ok(Some(frame)) if frame["t"] == "bye" => return true,
                Ok(Some(_)) => {}
                Err(_) => return false,
            }
        }
    }

    async fn request(&mut self) -> Value {
        self.send(json!({"t": "pair_request"})).await;
        self.recv().await.expect("an answer to the request")
    }
}

#[tokio::test]
async fn pairing_shows_equal_codes_and_writes_both_books() {
    let a = Device::start("Alpha", Visibility::Open).await;
    let b = Device::start("Beta", Visibility::Open).await;
    let prompt = pair(&a, &b).await;
    assert_eq!(prompt.id, a.id());
    assert_eq!(prompt.fingerprint, id::fingerprint(&a.id()));
    assert_eq!(prompt.name, "Alpha");
    assert_eq!(prompt.addr, IpAddr::from(Ipv4Addr::LOCALHOST));
    assert!(!prompt.known && !prompt.quiet);

    let b_id = b.id();
    let seen_by_a = a
        .state_where("B as opened from here", |s| {
            (s.devices.iter()).any(|d| d.id == b_id && d.opened_from_here)
        })
        .await;
    let device = seen_by_a.devices.iter().find(|d| d.id == b_id).unwrap();
    assert!(device.may_open_me.is_none() && device.name_verified && device.online);
    assert_eq!(device.name, "Beta");
    let a_id = a.id();
    let seen_by_b = b
        .state_where("A as trusted", |s| {
            (s.devices.iter()).any(|d| d.id == a_id && d.may_open_me.is_some())
        })
        .await;
    let device = seen_by_b.devices.iter().find(|d| d.id == a_id).unwrap();
    assert_eq!(device.may_open_me, Some(Grants::default()));
    assert!(!device.opened_from_here && device.name_verified);
    assert!(seen_by_b.pending.is_empty());

    assert!(listed(&a.store.book(), "paired", &b.id()));
    assert!(listed(&b.store.book(), "trusted", &a.id()));
    assert!(!listed(&a.store.book(), "trusted", &b.id()));
    assert!(b.lan.knows(&a.id()) && a.lan.knows(&b.id()));
    assert_eq!(b.lan.grants(&a.id()), Some(Grants::default()));
    assert_eq!(a.lan.grants(&b.id()), None);
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn allow_without_the_requesters_confirmation_writes_nothing() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    let c = Device::start("C", Visibility::Open).await;
    let (prompt, reply, code) = ask(&a, &b).await;
    reply.answer(PairDecision::Allow { remember: true });
    a.lan.confirm_pair(&b.id(), other_code(&code));
    a.lan.confirm_pair(&c.id(), &code);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!b.lan.knows(&a.id()) && !a.lan.knows(&b.id()));
    a.lan.cancel_pair(&b.id());
    assert_eq!(a.done(&b.id()).await, PairOutcome::Cancelled);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!b.heard(|s| matches!(
        s,
        LanSignal::Event(LanEvent::PromptClosed { request }) if *request == prompt.request
    )));
    assert!(!b.lan.knows(&a.id()) && !a.lan.knows(&b.id()));
    assert!(a.store.text().is_none() && b.store.text().is_none());

    let (prompt, _reply, _) = ask(&a, &b).await;
    a.lan.cancel_pair(&b.id());
    assert_eq!(a.done(&b.id()).await, PairOutcome::Cancelled);
    let pick = |s: &LanSignal| {
        matches!(
            s,
            LanSignal::Event(LanEvent::PromptClosed { request }) if *request == prompt.request
        )
    };
    b.take("PromptClosed", pick).await;

    let (_, reply, code) = ask(&a, &b).await;
    a.lan.confirm_pair(&b.id(), &code);
    reply.answer(PairDecision::Deny);
    assert_eq!(a.done(&b.id()).await, PairOutcome::Denied);
    assert!(!b.lan.knows(&a.id()) && !a.lan.knows(&b.id()));
    assert!(a.store.text().is_none() && b.store.text().is_none());
    a.stop().await;
    b.stop().await;
    c.stop().await;
}

#[tokio::test]
async fn deny_cools_down_and_block_shuts_out() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    let (_, reply, _) = ask(&a, &b).await;
    reply.answer(PairDecision::Deny);
    assert_eq!(a.done(&b.id()).await, PairOutcome::Denied);
    a.lan.pair(&b.id());
    let outcome = a.done(&b.id()).await;
    assert!(
        matches!(
            outcome,
            PairOutcome::Refused {
                code: RefuseCode::Cooldown,
                retry_after: Some(_)
            }
        ),
        "{outcome:?}"
    );
    a.stop().await;
    b.stop().await;

    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    let (_, reply, _) = ask(&a, &b).await;
    reply.answer(PairDecision::Block);
    assert_eq!(a.done(&b.id()).await, PairOutcome::Denied);
    a.lan.pair(&b.id());
    let outcome = a.done(&b.id()).await;
    assert!(matches!(outcome, PairOutcome::Failed(_)), "{outcome:?}");
    let state = b.lan.state();
    assert!(state.blocked.iter().any(|d| d.id == a.id()));
    assert!(state.devices.iter().all(|d| d.id != a.id()));
    let blocked = &b.store.book()["blocked"];
    assert_eq!(blocked[0]["id"], a.id());
    assert_eq!(blocked[0]["addr"], "127.0.0.1");
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn a_dropped_reply_answers_not_shown() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    let (_, reply, _) = ask(&a, &b).await;
    drop(reply);
    let started = Instant::now();
    assert_eq!(a.done(&b.id()).await, PairOutcome::NotShown);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(b.lan.state().pending.is_empty());
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn open_after_pairing_carries_signals_both_ways() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    pair(&a, &b).await;
    a.lan.session(&b.id(), None);
    a.until("the pairing tunnel closed", |lan| {
        !lan.send_rtc(&b.id(), candidate())
    })
    .await;
    let opened = a.lan.open(&b.id()).expect("a paired device");
    assert_ne!(opened.dial, 0);
    assert_eq!(a.lan.open(&b.id()), Some(opened));
    assert!(a.lan.dialing(&b.id()));
    assert!(a.lan.send_rtc(&b.id(), offer("first", false)));
    let key_of = |book: Value, list: &str| id::key_bytes(book[list][0]["key"].as_str().unwrap());
    let a_key = key_of(b.store.book(), "trusted").unwrap();
    assert_eq!(Some(opened.key), key_of(a.store.book(), "paired"));
    let (key, signal) = b.rtc(&a.id()).await;
    assert_eq!(key, a_key);
    assert!(matches!(signal, RtcSignal::Offer { sdp, ice_restart: false } if sdp == "first"));
    assert!(b.lan.send_rtc(&a.id(), offer("restart", true)));
    let (key, signal) = a.rtc(&b.id()).await;
    assert_eq!(key, opened.key);
    assert!(matches!(signal, RtcSignal::Offer { sdp, ice_restart: true } if sdp == "restart"));
    assert!(!a.lan.dialing(&b.id()));
    assert_eq!(
        a.lan.open(&b.id()),
        Some(p2p_node::lan::Opened {
            key: opened.key,
            dial: 0
        })
    );
    assert!(a.lan.open(&id::id_of_bytes(&[1; 32])).is_none());
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn an_open_waits_for_its_own_tunnel() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    pair(&a, &b).await;
    pair(&b, &a).await;
    a.lan.session(&b.id(), None);
    let port = b.lan.port().expect("a listener");
    b.lan.set_visibility(Visibility::Off);
    let deadline = Instant::now() + WAIT;
    let stalled = loop {
        match tokio::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await {
            Ok(stalled) => break stalled,
            Err(e) => {
                assert!(Instant::now() < deadline, "port {port} never freed: {e}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    let stall = tokio::spawn(async move {
        let (stream, _) = stalled.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(stream);
    });
    b.lan.set_visibility(Visibility::Open);
    a.knows_address_of(&b);

    let opened = a.lan.open(&b.id()).expect("paired");
    assert_ne!(opened.dial, 0);
    assert!(a.lan.send_rtc(&b.id(), offer("over my own tunnel", false)));
    let (_, signal) = b.rtc(&a.id()).await;
    assert!(matches!(signal, RtcSignal::Offer { sdp, .. } if sdp == "over my own tunnel"));
    b.lan.session(&a.id(), None);
    let answer = RtcSignal::Answer {
        sdp: "answer".to_string(),
    };
    assert!(b.lan.send_rtc(&a.id(), answer));
    let (_, signal) = a.rtc(&b.id()).await;
    assert!(matches!(signal, RtcSignal::Answer { sdp } if sdp == "answer"));
    assert!(!a.heard(|s| matches!(s, LanSignal::Unreachable { .. })));
    stall.abort();
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn forget_pushes_the_revocation() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    pair(&a, &b).await;
    assert!(a.lan.send_rtc(&b.id(), candidate()));
    b.lan.forget(&a.id());
    b.closed(&a.id()).await;
    a.unpaired(&b.id()).await;
    a.closed(&b.id()).await;
    assert!(!b.lan.knows(&a.id()) && !a.lan.knows(&b.id()));
    a.until("the tunnel gone", |lan| !lan.send_rtc(&b.id(), candidate()))
        .await;
    assert!(!listed(&b.store.book(), "trusted", &a.id()));
    assert!(!listed(&a.store.book(), "paired", &b.id()));
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn visibility_gates_the_listener() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    let c = Device::start("C", Visibility::Open).await;
    pair(&a, &b).await;
    b.lan.set_visibility(Visibility::TrustedOnly);
    assert!(b.lan.port().is_some());
    c.knows_address_of(&b);
    c.lan.pair(&b.id());
    let outcome = c.done(&b.id()).await;
    assert!(matches!(outcome, PairOutcome::Failed(_)), "{outcome:?}");
    fresh_tunnel(&a, &b).await;
    assert!(a.lan.send_rtc(&b.id(), offer("trusted only", false)));
    let (_, signal) = b.rtc(&a.id()).await;
    assert!(matches!(signal, RtcSignal::Offer { sdp, .. } if sdp == "trusted only"));

    b.lan.set_visibility(Visibility::Off);
    assert_eq!(b.lan.port(), None);
    a.until("the tunnel gone", |lan| !lan.send_rtc(&b.id(), candidate()))
        .await;
    let opened = a.lan.open(&b.id()).expect("still paired");
    let (dial, _) = a.unreachable(&b.id()).await;
    assert_eq!(dial, opened.dial);
    assert!(a.lan.knows(&b.id()));
    a.stop().await;
    b.stop().await;
    c.stop().await;
}

#[tokio::test]
async fn grants_and_re_pairing() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    pair(&a, &b).await;
    let terminal = Grants { terminal: true };
    assert!(b.lan.set_grants(&a.id(), terminal));
    assert!(!b.lan.set_grants(&a.id(), terminal));
    assert!(!b.lan.set_grants(&id::id_of_bytes(&[3; 32]), terminal));
    b.closed(&a.id()).await;
    a.until("the tunnel closed", |lan| {
        !lan.send_rtc(&b.id(), candidate())
    })
    .await;
    assert_eq!(b.store.book()["trusted"][0]["grants"]["terminal"], true);

    let (prompt, reply, code) = ask(&a, &b).await;
    assert!(prompt.known);
    reply.answer(PairDecision::Allow { remember: true });
    a.lan.confirm_pair(&b.id(), &code);
    assert_eq!(a.done(&b.id()).await, PairOutcome::Allowed);
    b.closed(&a.id()).await;
    assert_eq!(b.lan.grants(&a.id()), Some(terminal));

    a.lan.pair(&b.id());
    let _prompt = b.prompt().await;
    a.lan.cancel_pair(&b.id());
    assert_eq!(a.done(&b.id()).await, PairOutcome::Cancelled);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(a.lan.send_rtc(&b.id(), offer("still here", false)));
    let (_, signal) = b.rtc(&a.id()).await;
    assert!(matches!(signal, RtcSignal::Offer { sdp, .. } if sdp == "still here"));
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn stop_then_start_binds_the_same_port() {
    let key = generate_ed25519_keypair().0;
    let a = Device::with(
        "A",
        Visibility::Open,
        Arc::new(Memory::default()),
        key.clone(),
        false,
    )
    .await;
    let port = a.lan.port().expect("a listener");
    a.lan.stop().await;
    a.lan.stop().await;
    assert_eq!(a.lan.port(), None);
    a.lan.set_visibility(Visibility::TrustedOnly);
    a.lan.set_visibility(Visibility::Open);
    assert_eq!(a.lan.port(), None);
    a.lan.pair(&id::id_of_bytes(&[5; 32]));
    a.drain.abort();

    let (signals, _heard) = mpsc::channel(64);
    let config = LanConfig {
        name: "again".to_string(),
        os: "linux".to_string(),
        kind: "test".to_string(),
        visibility: Visibility::Open,
        browse: false,
        port,
        resources: vec![],
        trust: Arc::new(Memory::default()),
        test_mode: true,
    };
    let again = Lan::start(config, &key, signals).await.expect("lan");
    assert_eq!(again.port(), Some(port));
    again.stop().await;
}

#[tokio::test]
async fn devices_see_each_other_over_mdns() {
    let key = || generate_ed25519_keypair().0;
    let store = || Arc::new(Memory::default());
    let a = Device::with("Mdns A", Visibility::Open, store(), key(), true).await;
    let b = Device::with("Mdns B", Visibility::Open, store(), key(), true).await;
    let (a_id, b_id) = (a.id(), b.id());
    let state = a
        .state_where("B over mDNS", |s| s.devices.iter().any(|d| d.id == b_id))
        .await;
    let device = state.devices.iter().find(|d| d.id == b_id).unwrap();
    assert!(!device.name_verified && device.online);
    assert_eq!(device.name, "Mdns B");
    b.state_where("A over mDNS", |s| s.devices.iter().any(|d| d.id == a_id))
        .await;
    a.lan.browse(false);
    assert!(a.lan.state().devices.iter().all(|d| d.id != b_id));
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn a_revoked_pairing_is_dropped_on_open() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    pair(&a, &b).await;
    let a = a.restart().await;
    b.lan.forget(&a.id());
    b.closed(&a.id()).await;
    assert!(a.lan.knows(&b.id()));
    let opened = a.lan.open(&b.id()).expect("still paired here");
    a.unpaired(&b.id()).await;
    let (dial, reason) = a.unreachable(&b.id()).await;
    assert_eq!(dial, opened.dial);
    assert_eq!(reason, "it no longer accepts this device");
    assert!(!a.lan.knows(&b.id()));
    assert!(!listed(&a.store.book(), "paired", &b.id()));
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn the_book_survives_a_restart() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    let c = Device::start("C", Visibility::Open).await;
    pair_with(&a, &b, true).await;
    pair_with(&a, &c, false).await;
    assert!(c.lan.knows(&a.id()));
    assert!(c.store.text().is_some_and(|text| !text.contains(&a.id())));
    let b = b.restart().await;
    let c = c.restart().await;
    assert_eq!(b.lan.grants(&a.id()), Some(Grants::default()));
    assert!(!c.lan.knows(&a.id()));
    let a = a.restart().await;
    assert!(a.lan.knows(&b.id()) && a.lan.knows(&c.id()));
    a.stop().await;
    b.stop().await;
    c.stop().await;
}

#[tokio::test]
async fn a_crossing_pairing_is_refused() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    let (_, reply, code) = ask(&a, &b).await;
    b.knows_address_of(&a);
    b.lan.pair(&a.id());
    let outcome = b.done(&a.id()).await;
    assert_eq!(
        outcome,
        PairOutcome::Refused {
            code: RefuseCode::PairingBusy,
            retry_after: Some(Duration::from_secs(60))
        }
    );
    assert!(!a.heard(|s| matches!(s, LanSignal::Prompt(..))));
    reply.answer(PairDecision::Allow { remember: true });
    a.lan.confirm_pair(&b.id(), &code);
    assert_eq!(a.done(&b.id()).await, PairOutcome::Allowed);
    b.closed(&a.id()).await;
    assert!(b.lan.grants(&a.id()).is_some());
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn a_strangers_signal_closes_its_tunnel() {
    let b = Device::start("B", Visibility::Open).await;
    let mut raw = RawPeer::connect(b.addr()).await;
    raw.send(json!({"t": "rtc", "signal": {"type": "Offer", "payload": {"sdp": "x"}}}))
        .await;
    assert!(raw.closed_within(Duration::from_secs(1)).await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!b.heard(|s| matches!(s, LanSignal::Rtc { .. })));
    assert!(b.heard(|s| matches!(s, LanSignal::Log(line) if line.contains("unexpected frame"))));
    b.stop().await;
}

#[tokio::test]
async fn a_broken_nonce_does_not_pause_pairing() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    for _ in 0..3 {
        let mut raw = RawPeer::connect(b.addr()).await;
        let challenge = raw.request().await;
        assert_eq!(challenge["t"], "pair_challenge");
        let short = STANDARD_NO_PAD.encode(rand::random::<[u8; 31]>());
        raw.send(json!({"t": "pair_nonce", "nonce": short})).await;
        assert!(raw.closed_within(Duration::from_secs(1)).await);
    }
    assert!(!b.lan.state().paused);
    assert!(!b.heard(|s| matches!(s, LanSignal::Prompt(..))));
    pair(&a, &b).await;
    assert!(b.lan.knows(&a.id()));
    a.stop().await;
    b.stop().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn every_code_a_requester_learns_was_prompted_first() {
    let b = Device::start("B", Visibility::Open).await;
    let mut learned = Vec::new();
    let mut limited = 0;
    for last in 2..=9 {
        for _ in 0..7 {
            let mut raw = RawPeer::from(IpAddr::from([127, 0, 0, last]), b.addr()).await;
            let challenge = raw.request().await;
            if challenge["t"] == "pair_refused" {
                assert_eq!(challenge["code"], "rate_limited", "{challenge}");
                assert!(raw.closed_within(WAIT).await);
                limited += 1;
                continue;
            }
            assert_eq!(challenge["t"], "pair_challenge", "{challenge}");
            let nonce: [u8; 32] = rand::random();
            raw.send(json!({"t": "pair_nonce", "nonce": id::b64(&nonce)}))
                .await;
            let reveal = raw.recv().await.expect("a reveal");
            assert_eq!(reveal["t"], "pair_reveal", "{reveal}");
            let revealed = bytes_of(&reveal["nonce"]);
            assert_eq!(
                bytes_of(&challenge["commit"]),
                commitment(&raw.h, &revealed)
            );
            let request = challenge["request"].as_str().unwrap().to_string();
            learned.push((request, code_of(&raw.h, &nonce, &revealed)));
            raw.send(json!({"t": "pair_cancel"})).await;
            assert!(raw.closed_within(WAIT).await);
        }
    }
    assert_eq!((learned.len(), limited), (48, 8));
    for (i, (request, code)) in learned.iter().enumerate() {
        let pick = |s: &LanSignal| matches!(s, LanSignal::Prompt(p, _) if p.request == *request);
        let prompt = match b.take("the prompt of a learned code", pick).await {
            LanSignal::Prompt(prompt, _) => prompt,
            _ => unreachable!(),
        };
        assert_eq!(prompt.code, *code);
        assert_eq!(prompt.quiet, i >= 3, "{i}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!b.heard(|s| matches!(s, LanSignal::Prompt(..))));
    let state = b.lan.state();
    assert!(state.pending.is_empty() && !state.paused);
    b.stop().await;
}

#[tokio::test]
async fn a_reveal_that_does_not_open_its_commitment_fails_the_pairing() {
    for paired in [false, true] {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let signing = SigningKey::from_bytes(&rand::random());
        let key = id::b64(&signing.verifying_key().to_bytes());
        let b = id::id_of(&key).unwrap();
        let records = if paired {
            vec![json!({"id": b, "name": "B", "key": key, "added": 1})]
        } else {
            Vec::new()
        };
        let book = json!({"v": 1, "paired": records}).to_string();
        let store = Arc::new(Memory::holding(&book));
        let a_key = generate_ed25519_keypair().0;
        let a = Device::with("A", Visibility::Open, store.clone(), a_key, false).await;
        let answered = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut raw = RawPeer::answer(stream, &signing, "B", paired).await;
            assert_eq!(raw.recv().await.expect("a request")["t"], "pair_request");
            let nonce: [u8; 32] = rand::random();
            let commit = id::b64(&commitment(&raw.h, &nonce));
            let challenge = json!({
                "t": "pair_challenge",
                "request": "r",
                "expires_in_s": 120,
                "commit": commit,
            });
            raw.send(challenge).await;
            assert_eq!(raw.recv().await.expect("a nonce")["t"], "pair_nonce");
            let mut wrong = nonce;
            wrong[0] ^= 1;
            raw.send(json!({"t": "pair_reveal", "nonce": id::b64(&wrong)}))
                .await;
            let mut after = Vec::new();
            loop {
                match tokio::time::timeout(WAIT, raw.recv()).await {
                    Ok(Some(frame)) if frame["t"] == "bye" => return (true, after),
                    Ok(Some(frame)) => after.push(frame),
                    Ok(None) => return (true, after),
                    Err(_) => return (false, after),
                }
            }
        });
        a.lan.add_address(&b, addr);
        if paired {
            a.lan.open(&b).expect("a paired device");
            a.until("the admitted tunnel", |lan| !lan.dialing(&b)).await;
        }
        a.lan.pair(&b);
        assert_eq!(
            a.done(&b).await,
            PairOutcome::Failed("the device's code did not check out".to_string())
        );
        let (closed, after) = answered.await.unwrap();
        assert!(closed && after.is_empty(), "{paired} {after:?}");
        assert!(!a.heard(|s| matches!(s, LanSignal::Event(LanEvent::PairWaiting { .. }))));
        assert_eq!(a.lan.knows(&b), paired);
        assert_eq!(store.text(), Some(book));
        a.stop().await;
    }
}

#[tokio::test]
async fn an_unrevealed_request_frees_its_place() {
    let b = Device::start("B", Visibility::Open).await;
    let d = Device::start("D", Visibility::Open).await;
    let mut silent = Vec::new();
    for _ in 0..3 {
        let mut raw = RawPeer::connect(b.addr()).await;
        assert_eq!(raw.request().await["t"], "pair_challenge");
        silent.push(raw);
    }
    d.knows_address_of(&b);
    d.lan.pair(&b.id());
    let outcome = d.done(&b.id()).await;
    assert!(
        matches!(
            outcome,
            PairOutcome::Refused {
                code: RefuseCode::PairingBusy,
                ..
            }
        ),
        "{outcome:?}"
    );
    tokio::time::sleep(Duration::from_secs(11)).await;
    for raw in &mut silent {
        assert!(raw.closed_within(Duration::from_millis(100)).await);
    }
    pair(&d, &b).await;
    assert!(b.lan.knows(&d.id()));
    b.stop().await;
    d.stop().await;
}

#[tokio::test]
async fn a_device_without_a_name_cannot_ask() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    let refused = json!({"t": "pair_refused", "code": "no_name", "retry_after_s": null});
    for _ in 0..7 {
        let mut raw = RawPeer::named(b.addr(), " \u{202e}\t").await;
        assert_eq!(raw.request().await, refused);
        assert!(raw.closed_within(Duration::from_secs(1)).await);
    }
    assert!(!b.heard(|s| matches!(s, LanSignal::Prompt(..))));
    assert!(!b.lan.state().paused);
    pair(&a, &b).await;
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn a_device_without_a_name_is_not_asked() {
    let a = Device::start("A", Visibility::Open).await;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let signing = SigningKey::from_bytes(&rand::random());
    let nameless = id::id_of_bytes(&signing.verifying_key().to_bytes());
    let answered = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut raw = RawPeer::answer(stream, &signing, "\u{200f}", false).await;
        let mut heard = Vec::new();
        while let Ok(Some(frame)) = tokio::time::timeout(Duration::from_secs(1), raw.recv()).await {
            heard.push(frame);
        }
        heard
    });
    a.lan.add_address(&nameless, addr);
    a.lan.pair(&nameless);
    assert_eq!(
        a.done(&nameless).await,
        PairOutcome::Failed("the device has no name".to_string())
    );
    let heard = answered.await.unwrap();
    assert!(
        heard.iter().all(|frame| frame["t"] != "pair_request"),
        "{heard:?}"
    );
    a.stop().await;
}

#[tokio::test]
async fn a_block_on_a_trusted_devices_address_does_not_lock_it_out() {
    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    let c = Device::start("C", Visibility::Open).await;
    let d = Device::start("D", Visibility::Open).await;
    pair(&a, &b).await;
    let (_, reply, _) = ask(&c, &b).await;
    reply.answer(PairDecision::Block);
    assert_eq!(c.done(&b.id()).await, PairOutcome::Denied);
    assert_eq!(b.store.book()["blocked"][0]["addr"], "127.0.0.1");
    fresh_tunnel(&a, &b).await;
    assert!(a
        .lan
        .send_rtc(&b.id(), offer("from a trusted device", false)));
    b.rtc(&a.id()).await;
    d.knows_address_of(&b);
    d.lan.pair(&b.id());
    let outcome = d.done(&b.id()).await;
    assert_eq!(
        outcome,
        PairOutcome::Failed("the device closed the connection".to_string())
    );
    a.stop().await;
    b.stop().await;
    c.stop().await;
    d.stop().await;
}

#[tokio::test]
async fn blocking_a_device_known_only_from_mdns_stores_no_address() {
    let b = Device::start("B", Visibility::Open).await;
    let x = id::id_of_bytes(&[7; 32]);
    b.lan.add_address(&x, "127.0.0.1:9".parse().unwrap());
    b.lan.block(&x);
    b.closed(&x).await;
    let blocked = &b.store.book()["blocked"];
    assert_eq!(blocked[0]["id"], x.as_str());
    assert_eq!(blocked[0]["name"], id::id8(&x));
    assert!(blocked[0]["addr"].is_null());
    assert_eq!(b.lan.state().blocked[0].id, x);
    b.lan.unblock(&x);
    assert!(b.lan.state().blocked.is_empty());
    assert_eq!(b.store.book()["blocked"].as_array().map(Vec::len), Some(0));
    b.stop().await;
}

#[tokio::test]
async fn an_unreadable_book_is_never_overwritten() {
    let c = Device::start("C", Visibility::Open).await;
    let newer = r#"{"v":2,"trusted":[],"paired":[],"future":true}"#;
    let stores = [
        Arc::new(Memory::holding(newer)),
        Arc::new(Memory {
            unreadable: true,
            ..Memory::holding("whatever was there")
        }),
    ];
    for store in stores {
        let before = store.text();
        let key = generate_ed25519_keypair().0;
        let u = Device::with("U", Visibility::Open, store.clone(), key, false).await;
        assert!(u.not_saved().await.contains("cannot be read"));
        assert_eq!(u.lan.port(), None);
        assert_eq!(u.lan.state().port, 0);
        let (_, reply, code) = ask(&u, &c).await;
        reply.answer(PairDecision::Allow { remember: true });
        u.lan.confirm_pair(&c.id(), &code);
        assert_eq!(u.done(&c.id()).await, PairOutcome::Allowed);
        assert!(u.not_saved().await.contains("was not saved"));
        assert_eq!(store.text(), before);
        u.stop().await;
    }

    let refusing = Arc::new(Memory {
        refuses: true,
        ..Memory::default()
    });
    let key = generate_ed25519_keypair().0;
    let r = Device::with("R", Visibility::Open, refusing.clone(), key, false).await;
    assert!(r.lan.port().is_some());
    pair(&c, &r).await;
    assert!(r.not_saved().await.contains("read-only"));
    assert!(r.lan.knows(&c.id()));
    assert_eq!(refusing.text(), None);
    r.stop().await;
    c.stop().await;
}

#[tokio::test]
async fn a_lost_port_is_rebound_elsewhere() {
    let b = Device::start("B", Visibility::Open).await;
    let port = b.lan.port().expect("a listener");
    b.lan.set_visibility(Visibility::Off);
    assert_eq!(b.lan.port(), None);
    let deadline = Instant::now() + WAIT;
    let _held = loop {
        match std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) {
            Ok(held) => break held,
            Err(e) => {
                assert!(Instant::now() < deadline, "port {port} never freed: {e}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    b.lan.set_visibility(Visibility::Open);
    let rebound = b.lan.port().expect("a listener again");
    assert_ne!(rebound, port);
    b.stop().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn pre_trust_caps_hold() {
    async fn eof_within(stream: &mut TcpStream, wait: Duration) -> bool {
        let mut byte = [0u8; 1];
        matches!(
            tokio::time::timeout(wait, stream.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    let a = Device::start("A", Visibility::Open).await;
    let b = Device::start("B", Visibility::Open).await;
    pair(&a, &b).await;
    a.lan.session(&b.id(), None);
    a.until("the pairing tunnel closed", |lan| {
        !lan.send_rtc(&b.id(), candidate())
    })
    .await;

    let addr = b.addr();
    let silent = |last: u8| async move {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket
            .bind(SocketAddr::from(([127, 0, 0, last], 0)))
            .unwrap();
        socket.connect(addr).await.unwrap()
    };
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(silent(2).await);
    }
    let mut ninth = silent(2).await;
    assert!(eof_within(&mut ninth, Duration::from_secs(1)).await);
    for last in 3..=5 {
        for _ in 0..8 {
            held.push(silent(last).await);
        }
    }
    let mut extra = silent(6).await;
    assert!(eof_within(&mut extra, Duration::from_secs(1)).await);
    assert!(!eof_within(&mut held[0], Duration::from_millis(200)).await);

    let opened = a.lan.open(&b.id()).expect("paired");
    assert_ne!(opened.dial, 0);
    assert!(a.lan.send_rtc(&b.id(), offer("through the reserve", false)));
    let (_, signal) = b.rtc(&a.id()).await;
    assert!(matches!(signal, RtcSignal::Offer { sdp, .. } if sdp == "through the reserve"));
    assert!(!a.heard(|s| matches!(s, LanSignal::Unreachable { .. })));
    a.stop().await;
    b.stop().await;
}
