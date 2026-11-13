use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use nodeinnet_p2p::RtcSignal;
use serde::{Deserialize, Serialize};
use snow::params::NoiseParams;
use snow::{Builder, StatelessTransportState};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::lan::{id, pairing, sas, PairOutcome, RefuseCode};

const PROLOGUE: &[u8] = b"nodeinnet-lan/1";
const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
const VERSION: u32 = 1;
const MAX_MESSAGE: usize = 65535;
const TAG: usize = 16;
const HANDSHAKE_MAX: usize = 1024;
const CONNECT: Duration = Duration::from_secs(3);
const DIAL_HELLO: Duration = Duration::from_secs(10);
const ACCEPT_HELLO: Duration = Duration::from_secs(5);
pub(crate) const STRANGER_START: Duration = Duration::from_secs(10);
const CHALLENGE_WAIT: Duration = Duration::from_secs(10);
const RESULT_GRACE: Duration = Duration::from_secs(5);
const EXPIRES_MAX: Duration = Duration::from_secs(300);
const RETRY_MAX: Duration = Duration::from_secs(86_400);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_TIME: Duration = Duration::from_secs(15);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const KEEPALIVE_RETRIES: u32 = 3;
#[cfg(any(target_os = "linux", target_os = "android"))]
const USER_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const QUEUE: usize = 256;
const UNADMITTED_MAX: usize = 32;
const PER_IP_MAX: usize = 8;
const RESERVED: usize = 8;
const RESERVED_PER_IP: usize = 2;

#[derive(Debug)]
pub(crate) enum TunnelError {
    Io(io::Error),
    Timeout,
    Noise,
    Protocol(&'static str),
    BadHello,
    WrongId(String),
    TooLarge,
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelError::Io(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                ) =>
            {
                f.write_str("the device closed the connection")
            }
            TunnelError::Io(e) => write!(f, "unreachable ({e})"),
            TunnelError::Timeout => f.write_str("no answer in time"),
            TunnelError::Noise => f.write_str("secure handshake failed"),
            TunnelError::Protocol(what) => write!(f, "protocol error: {what}"),
            TunnelError::BadHello => f.write_str("the device did not prove its key"),
            TunnelError::WrongId(_) => f.write_str("it answered as another device"),
            TunnelError::TooLarge => f.write_str("message too large"),
        }
    }
}

impl From<io::Error> for TunnelError {
    fn from(e: io::Error) -> Self {
        TunnelError::Io(e)
    }
}

impl From<snow::Error> for TunnelError {
    fn from(_: snow::Error) -> Self {
        TunnelError::Noise
    }
}

async fn read_message<R: AsyncRead + Unpin>(
    r: &mut R,
    min: usize,
    max: usize,
) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len < min || len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message length out of bounds",
        ));
    }
    let mut msg = vec![0; len];
    r.read_exact(&mut msg).await?;
    Ok(msg)
}

async fn write_message<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(4 + msg.len());
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    w.write_all(&out).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Initiator,
    Responder,
}

async fn noise<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    rd: &mut R,
    wr: &mut W,
    role: Role,
) -> Result<([u8; 32], StatelessTransportState), TunnelError> {
    let params: NoiseParams = PARAMS.parse()?;
    let keypair = Builder::new(params.clone()).generate_keypair()?;
    let builder = Builder::new(params)
        .prologue(PROLOGUE)
        .local_private_key(&keypair.private);
    let mut hs = match role {
        Role::Initiator => builder.build_initiator()?,
        Role::Responder => builder.build_responder()?,
    };
    let mut out = [0u8; HANDSHAKE_MAX];
    let mut payload = [0u8; HANDSHAKE_MAX];
    let mut writes = role == Role::Initiator;
    while !hs.is_handshake_finished() {
        if writes {
            let n = hs.write_message(&[], &mut out)?;
            write_message(wr, &out[..n]).await?;
        } else {
            let msg = read_message(rd, 1, HANDSHAKE_MAX).await?;
            hs.read_message(&msg, &mut payload)?;
        }
        writes = !writes;
    }
    let h: [u8; 32] = hs
        .get_handshake_hash()
        .try_into()
        .map_err(|_| TunnelError::Protocol("handshake hash"))?;
    Ok((h, hs.into_stateless_transport_mode()?))
}

pub(crate) struct Identity {
    signing: SigningKey,
    pub(crate) key: [u8; 32],
    pub(crate) id: String,
}

impl Identity {
    pub(crate) fn from_private(private: &str) -> Result<Identity, &'static str> {
        let seed: [u8; 32] = id::from_b64(private)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or("not a 32-byte key in base64")?;
        let signing = SigningKey::from_bytes(&seed);
        let key = signing.verifying_key().to_bytes();
        Ok(Identity {
            signing,
            key,
            id: id::id_of_bytes(&key),
        })
    }

    pub(crate) fn hello(&self, card: &Card, role: Role, h: &[u8; 32]) -> LanFrame {
        LanFrame::Hello {
            v: VERSION,
            key: id::b64(&self.key),
            name: card.name.clone(),
            os: card.os.clone(),
            kind: card.kind.clone(),
            sig: id::b64(&self.signing.sign(&hello_message(role, h)).to_bytes()),
        }
    }
}

fn hello_message(role: Role, h: &[u8; 32]) -> Vec<u8> {
    let mut msg = b"nin-lan/1 hello".to_vec();
    msg.push(match role {
        Role::Initiator => b'I',
        Role::Responder => b'R',
    });
    msg.extend_from_slice(h);
    msg
}

pub(crate) fn verify_hello(frame: LanFrame, role: Role, h: &[u8; 32]) -> Result<Peer, TunnelError> {
    let LanFrame::Hello {
        v,
        key,
        name,
        os,
        kind,
        sig,
    } = frame
    else {
        return Err(TunnelError::Protocol("expected hello"));
    };
    if v != VERSION {
        return Err(TunnelError::Protocol("version"));
    }
    let key: [u8; 32] = id::from_b64(&key)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(TunnelError::BadHello)?;
    let sig: [u8; 64] = id::from_b64(&sig)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(TunnelError::BadHello)?;
    let verifying = VerifyingKey::from_bytes(&key).map_err(|_| TunnelError::BadHello)?;
    verifying
        .verify_strict(&hello_message(role, h), &Signature::from_bytes(&sig))
        .map_err(|_| TunnelError::BadHello)?;
    Ok(Peer {
        id: id::id_of_bytes(&key),
        key,
        name: id::sanitize_name(&name),
        os: id::sanitize_name(&os),
        kind: id::sanitize_name(&kind),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Peer {
    pub(crate) id: String,
    pub(crate) key: [u8; 32],
    pub(crate) name: String,
    pub(crate) os: String,
    pub(crate) kind: String,
}

impl Peer {
    pub(crate) fn hello(&self) -> pairing::Hello {
        pairing::Hello {
            id: self.id.clone(),
            name: self.name.clone(),
            kind: self.kind.clone(),
            os: self.os.clone(),
            key: id::b64(&self.key),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Card {
    pub(crate) name: String,
    pub(crate) os: String,
    pub(crate) kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum LanFrame {
    Hello {
        v: u32,
        key: String,
        name: String,
        os: String,
        kind: String,
        sig: String,
    },
    Status {
        trusted: bool,
    },
    PairRequest,
    PairChallenge {
        request: String,
        expires_in_s: u64,
        commit: String,
    },
    PairNonce {
        nonce: String,
    },
    PairReveal {
        nonce: String,
    },
    PairConfirm,
    PairResult {
        outcome: WireOutcome,
    },
    PairRefused {
        code: RefuseCode,
        retry_after_s: Option<u64>,
    },
    PairCancel,
    Rtc {
        signal: RtcSignal,
    },
    Bye,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WireOutcome {
    Allowed,
    Denied,
    Expired,
    NotShown,
    #[serde(other)]
    Other,
}

fn seal(
    cipher: &StatelessTransportState,
    n: &mut u64,
    frame: &LanFrame,
) -> Result<Vec<u8>, TunnelError> {
    let json = serde_json::to_vec(frame).map_err(|_| TunnelError::Protocol("bad frame"))?;
    if json.len() + TAG > MAX_MESSAGE {
        return Err(TunnelError::TooLarge);
    }
    let mut out = vec![0; json.len() + TAG];
    let len = cipher.write_message(*n, &json, &mut out)?;
    *n += 1;
    out.truncate(len);
    Ok(out)
}

fn open(
    cipher: &StatelessTransportState,
    n: &mut u64,
    msg: &[u8],
) -> Result<LanFrame, TunnelError> {
    let mut out = vec![0; msg.len()];
    let len = cipher.read_message(*n, msg, &mut out)?;
    *n += 1;
    out.truncate(len);
    serde_json::from_slice(&out).map_err(|_| TunnelError::Protocol("bad frame"))
}

pub(crate) struct Reader<R> {
    rd: R,
    cipher: Arc<StatelessTransportState>,
    n: u64,
}

pub(crate) struct Writer<W> {
    wr: W,
    cipher: Arc<StatelessTransportState>,
    n: u64,
}

pub(crate) struct Established<R, W> {
    pub(crate) reader: Reader<R>,
    pub(crate) writer: Writer<W>,
    pub(crate) h: [u8; 32],
    pub(crate) peer: Peer,
    pub(crate) trusted: bool,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    pub(crate) async fn next(&mut self) -> Result<LanFrame, TunnelError> {
        let msg = read_message(&mut self.rd, TAG, MAX_MESSAGE).await?;
        open(&self.cipher, &mut self.n, &msg)
    }
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    pub(crate) async fn send(&mut self, frame: &LanFrame) -> Result<(), TunnelError> {
        let msg = seal(&self.cipher, &mut self.n, frame)?;
        write_message(&mut self.wr, &msg).await?;
        Ok(())
    }
}

fn halves<R, W>(rd: R, wr: W, cipher: StatelessTransportState) -> (Reader<R>, Writer<W>) {
    let cipher = Arc::new(cipher);
    let reader = Reader {
        rd,
        cipher: cipher.clone(),
        n: 0,
    };
    (reader, Writer { wr, cipher, n: 0 })
}

pub(crate) async fn initiate<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut rd: R,
    mut wr: W,
    me: &Identity,
    card: &Card,
    expect: &str,
) -> Result<Established<R, W>, TunnelError> {
    let (h, cipher) = noise(&mut rd, &mut wr, Role::Initiator).await?;
    let (mut reader, mut writer) = halves(rd, wr, cipher);
    writer.send(&me.hello(card, Role::Initiator, &h)).await?;
    let peer = verify_hello(reader.next().await?, Role::Responder, &h)?;
    if peer.id == me.id {
        return Err(TunnelError::Protocol("own id"));
    }
    if peer.id != expect {
        return Err(TunnelError::WrongId(peer.id));
    }
    let LanFrame::Status { trusted } = reader.next().await? else {
        return Err(TunnelError::Protocol("no status"));
    };
    Ok(Established {
        reader,
        writer,
        h,
        peer,
        trusted,
    })
}

pub(crate) async fn respond<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut rd: R,
    mut wr: W,
    me: &Identity,
) -> Result<Established<R, W>, TunnelError> {
    let (h, cipher) = noise(&mut rd, &mut wr, Role::Responder).await?;
    let (mut reader, writer) = halves(rd, wr, cipher);
    let peer = verify_hello(reader.next().await?, Role::Initiator, &h)?;
    if peer.id == me.id {
        return Err(TunnelError::Protocol("own id"));
    }
    Ok(Established {
        reader,
        writer,
        h,
        peer,
        trusted: false,
    })
}

pub(crate) async fn dial(
    addr: SocketAddr,
    me: &Identity,
    card: &Card,
    expect: &str,
) -> Result<Established<OwnedReadHalf, OwnedWriteHalf>, TunnelError> {
    let stream = timeout(CONNECT, TcpStream::connect(addr))
        .await
        .map_err(|_| TunnelError::Timeout)??;
    tune(&stream);
    let (rd, wr) = stream.into_split();
    timeout(DIAL_HELLO, initiate(rd, wr, me, card, expect))
        .await
        .map_err(|_| TunnelError::Timeout)?
}

pub(crate) async fn accept(
    stream: TcpStream,
    me: &Identity,
) -> Result<Established<OwnedReadHalf, OwnedWriteHalf>, TunnelError> {
    tune(&stream);
    let (rd, wr) = stream.into_split();
    timeout(ACCEPT_HELLO, respond(rd, wr, me))
        .await
        .map_err(|_| TunnelError::Timeout)?
}

fn tune(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let socket = SockRef::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(KEEPALIVE_TIME)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    let _ = socket.set_tcp_keepalive(&keepalive);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _ = socket.set_tcp_user_timeout(Some(USER_TIMEOUT));
}

pub(crate) async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: Writer<W>,
    mut queue: mpsc::Receiver<LanFrame>,
) {
    while let Some(frame) = queue.recv().await {
        match timeout(WRITE_TIMEOUT, writer.send(&frame)).await {
            Ok(Ok(())) | Ok(Err(TunnelError::TooLarge)) => {}
            _ => break,
        }
        if matches!(frame, LanFrame::Bye) {
            break;
        }
    }
    let _ = timeout(Duration::from_secs(1), writer.wr.shutdown()).await;
}

#[derive(Default)]
struct Held {
    general: usize,
    reserved: usize,
    per_ip: HashMap<IpAddr, usize>,
    reserved_per_ip: HashMap<IpAddr, usize>,
}

#[derive(Default)]
pub(crate) struct Slots(Mutex<Held>);

pub(crate) struct Slot {
    slots: Arc<Slots>,
    ip: IpAddr,
    reserved: bool,
}

impl Slots {
    pub(crate) fn take(self: &Arc<Self>, ip: IpAddr, trusted_ip: bool) -> Option<Slot> {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if held.per_ip.get(&ip).copied().unwrap_or(0) >= PER_IP_MAX {
            return None;
        }
        let reserved_here = held.reserved_per_ip.get(&ip).copied().unwrap_or(0);
        let reserved = if held.general < UNADMITTED_MAX {
            held.general += 1;
            false
        } else if trusted_ip && held.reserved < RESERVED && reserved_here < RESERVED_PER_IP {
            held.reserved += 1;
            *held.reserved_per_ip.entry(ip).or_default() += 1;
            true
        } else {
            return None;
        };
        *held.per_ip.entry(ip).or_default() += 1;
        Some(Slot {
            slots: self.clone(),
            ip,
            reserved,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self.slots.0.lock().unwrap_or_else(PoisonError::into_inner);
        if self.reserved {
            held.reserved = held.reserved.saturating_sub(1);
            count_down(&mut held.reserved_per_ip, self.ip);
        } else {
            held.general = held.general.saturating_sub(1);
        }
        count_down(&mut held.per_ip, self.ip);
    }
}

fn count_down(counts: &mut HashMap<IpAddr, usize>, ip: IpAddr) {
    if let Some(count) = counts.get_mut(&ip) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(&ip);
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Step {
    pub(crate) send: Vec<LanFrame>,
    pub(crate) code: Option<String>,
    pub(crate) done: Option<PairOutcome>,
}

impl Step {
    fn ended(outcome: PairOutcome) -> Step {
        Step {
            done: Some(outcome),
            ..Step::default()
        }
    }
}

pub(crate) enum Asker {
    Requested {
        h: [u8; 32],
        until: Instant,
    },
    Challenged {
        sas: Option<sas::Initiator>,
        expires: Instant,
        until: Instant,
    },
    Comparing {
        code: String,
        confirmed: bool,
        allowed: bool,
        until: Instant,
    },
}

impl Asker {
    pub(crate) fn start(h: [u8; 32], now: Instant) -> (Asker, LanFrame) {
        let asker = Asker::Requested {
            h,
            until: now + CHALLENGE_WAIT,
        };
        (asker, LanFrame::PairRequest)
    }

    pub(crate) fn on_frame(&mut self, frame: &LanFrame, now: Instant) -> Option<Step> {
        match (&mut *self, frame) {
            (
                Asker::Requested { h, .. },
                LanFrame::PairChallenge {
                    expires_in_s,
                    commit,
                    ..
                },
            ) => {
                let commit: Option<[u8; 32]> =
                    id::from_b64(commit).and_then(|bytes| bytes.try_into().ok());
                let Some(commit) = commit else {
                    return Some(Step::ended(PairOutcome::Failed("broken challenge".into())));
                };
                let initiator = sas::Initiator::new(*h, commit);
                let nonce = id::b64(&initiator.nonce());
                let wait = Duration::from_secs(*expires_in_s).min(EXPIRES_MAX);
                *self = Asker::Challenged {
                    sas: Some(initiator),
                    expires: now + wait + RESULT_GRACE,
                    until: now + CHALLENGE_WAIT,
                };
                Some(Step {
                    send: vec![LanFrame::PairNonce { nonce }],
                    code: None,
                    done: None,
                })
            }
            (Asker::Challenged { sas, expires, .. }, LanFrame::PairReveal { nonce }) => {
                let nonce: Option<[u8; sas::NONCE_LEN]> =
                    id::from_b64(nonce).and_then(|bytes| bytes.try_into().ok());
                let code =
                    (nonce.zip(sas.take())).and_then(|(nonce, initiator)| initiator.code(&nonce));
                let Some(code) = code else {
                    return Some(Step::ended(PairOutcome::Failed(
                        "the device's code did not check out".into(),
                    )));
                };
                *self = Asker::Comparing {
                    code: code.clone(),
                    confirmed: false,
                    allowed: false,
                    until: *expires,
                };
                Some(Step {
                    code: Some(code),
                    ..Step::default()
                })
            }
            (
                _,
                LanFrame::PairRefused {
                    code,
                    retry_after_s,
                },
            ) => Some(Step::ended(PairOutcome::Refused {
                code: *code,
                retry_after: retry_after_s.map(|s| Duration::from_secs(s).min(RETRY_MAX)),
            })),
            (
                Asker::Challenged { .. } | Asker::Comparing { .. },
                LanFrame::PairResult { outcome },
            ) => {
                let done = match (outcome, &mut *self) {
                    (
                        WireOutcome::Allowed,
                        Asker::Comparing {
                            confirmed, allowed, ..
                        },
                    ) => {
                        *allowed = true;
                        confirmed.then_some(PairOutcome::Allowed)
                    }
                    (WireOutcome::Allowed, _) => return None,
                    (WireOutcome::Denied, _) => Some(PairOutcome::Denied),
                    (WireOutcome::Expired, _) => Some(PairOutcome::Expired),
                    (WireOutcome::NotShown, _) => Some(PairOutcome::NotShown),
                    (WireOutcome::Other, _) => Some(PairOutcome::Failed("unknown answer".into())),
                };
                Some(Step {
                    done,
                    ..Step::default()
                })
            }
            _ => None,
        }
    }

    pub(crate) fn confirm(&mut self, code: &str) -> Option<Step> {
        let Asker::Comparing {
            code: shown,
            confirmed,
            allowed,
            ..
        } = self
        else {
            return None;
        };
        if shown != code {
            return None;
        }
        if *confirmed {
            return Some(Step::default());
        }
        *confirmed = true;
        Some(Step {
            send: vec![LanFrame::PairConfirm],
            code: None,
            done: allowed.then_some(PairOutcome::Allowed),
        })
    }

    pub(crate) fn until(&self) -> Instant {
        match self {
            Asker::Requested { until, .. }
            | Asker::Challenged { until, .. }
            | Asker::Comparing { until, .. } => *until,
        }
    }

    pub(crate) fn challenged(&self) -> bool {
        matches!(self, Asker::Challenged { .. })
    }

    pub(crate) fn comparing(&self) -> bool {
        matches!(self, Asker::Comparing { .. })
    }

    pub(crate) fn timed_out(&self) -> PairOutcome {
        match self {
            Asker::Requested { .. } | Asker::Challenged { .. } => {
                PairOutcome::Failed("no answer in time".into())
            }
            Asker::Comparing { .. } => PairOutcome::Expired,
        }
    }
}

pub(crate) enum Answerer {
    Challenged {
        request: String,
        sas: Option<sas::Responder>,
        expires: Instant,
        until: Instant,
    },
    Prompted {
        request: String,
        reveal: Option<[u8; sas::NONCE_LEN]>,
        expires: Instant,
        allowed: Option<bool>,
        confirmed: bool,
    },
}

impl Answerer {
    pub(crate) fn challenge(
        h: [u8; 32],
        request: String,
        expires_in: Duration,
        expires: Instant,
        now: Instant,
    ) -> (Answerer, LanFrame) {
        let sas = sas::Responder::new(h);
        let frame = LanFrame::PairChallenge {
            request: request.clone(),
            expires_in_s: expires_in.as_secs(),
            commit: id::b64(&sas.commit()),
        };
        let answerer = Answerer::Challenged {
            request,
            sas: Some(sas),
            expires,
            until: (now + CHALLENGE_WAIT).min(expires),
        };
        (answerer, frame)
    }

    pub(crate) fn nonce(&mut self, nonce: &[u8; sas::NONCE_LEN]) -> Option<String> {
        let Answerer::Challenged {
            request,
            sas,
            expires,
            ..
        } = self
        else {
            return None;
        };
        let (reveal, code) = sas.take()?.reveal(nonce);
        *self = Answerer::Prompted {
            request: std::mem::take(request),
            reveal: Some(reveal),
            expires: *expires,
            allowed: None,
            confirmed: false,
        };
        Some(code)
    }

    pub(crate) fn reveal(&mut self) -> Option<LanFrame> {
        let Answerer::Prompted { reveal, .. } = self else {
            return None;
        };
        let nonce = reveal.take()?;
        Some(LanFrame::PairReveal {
            nonce: id::b64(&nonce),
        })
    }

    pub(crate) fn allow(&mut self, remember: bool) -> Step {
        let Answerer::Prompted {
            allowed: allowed @ None,
            confirmed,
            ..
        } = self
        else {
            return Step::default();
        };
        *allowed = Some(remember);
        Step {
            send: vec![LanFrame::PairResult {
                outcome: WireOutcome::Allowed,
            }],
            code: None,
            done: confirmed.then_some(PairOutcome::Allowed),
        }
    }

    pub(crate) fn confirm(&mut self) -> Option<Step> {
        let Answerer::Prompted {
            allowed, confirmed, ..
        } = self
        else {
            return None;
        };
        if *confirmed {
            return Some(Step::default());
        }
        *confirmed = true;
        Some(Step {
            done: allowed.is_some().then_some(PairOutcome::Allowed),
            ..Step::default()
        })
    }

    pub(crate) fn end(&mut self, outcome: WireOutcome) -> Step {
        let done = match outcome {
            WireOutcome::Expired => PairOutcome::Expired,
            WireOutcome::NotShown => PairOutcome::NotShown,
            _ => PairOutcome::Denied,
        };
        Step {
            send: vec![LanFrame::PairResult { outcome }],
            code: None,
            done: Some(done),
        }
    }

    pub(crate) fn request(&self) -> &str {
        match self {
            Answerer::Challenged { request, .. } | Answerer::Prompted { request, .. } => request,
        }
    }

    pub(crate) fn remember(&self) -> bool {
        matches!(
            self,
            Answerer::Prompted {
                allowed: Some(true),
                ..
            }
        )
    }

    pub(crate) fn challenged(&self) -> bool {
        matches!(self, Answerer::Challenged { .. })
    }

    pub(crate) fn undecided(&self) -> bool {
        matches!(self, Answerer::Prompted { allowed: None, .. })
    }

    pub(crate) fn until(&self) -> Instant {
        match self {
            Answerer::Challenged { until, .. } => *until,
            Answerer::Prompted {
                expires,
                allowed: None,
                ..
            } => *expires,
            Answerer::Prompted { expires, .. } => *expires + RESULT_GRACE,
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};

    use super::*;

    const EXPIRES: Duration = Duration::from_secs(120);

    type End = (ReadHalf<DuplexStream>, WriteHalf<DuplexStream>);

    fn pipe() -> (End, End) {
        let (a, b) = tokio::io::duplex(4 * MAX_MESSAGE);
        (tokio::io::split(a), tokio::io::split(b))
    }

    fn identity(seed: u8) -> Identity {
        Identity::from_private(&id::b64(&[seed; 32])).unwrap()
    }

    fn card(name: &str) -> Card {
        Card {
            name: name.into(),
            os: "linux".into(),
            kind: "desktop".into(),
        }
    }

    async fn answer<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        rd: R,
        wr: W,
        me: &Identity,
        trusted: bool,
    ) -> Result<Established<R, W>, TunnelError> {
        let mut est = respond(rd, wr, me).await?;
        let hello = me.hello(&card("R"), Role::Responder, &est.h);
        est.writer.send(&hello).await?;
        est.writer.send(&LanFrame::Status { trusted }).await?;
        Ok(est)
    }

    async fn transports() -> (StatelessTransportState, StatelessTransportState) {
        let ((mut ar, mut aw), (mut br, mut bw)) = pipe();
        let (a, b) = tokio::join!(
            noise(&mut ar, &mut aw, Role::Initiator),
            noise(&mut br, &mut bw, Role::Responder)
        );
        let ((a_h, a), (b_h, b)) = (a.unwrap(), b.unwrap());
        assert_eq!(a_h, b_h);
        (a, b)
    }

    fn commit_of(frame: &LanFrame) -> [u8; 32] {
        let LanFrame::PairChallenge { commit, .. } = frame else {
            panic!("{frame:?}");
        };
        id::from_b64(commit).unwrap().try_into().unwrap()
    }

    fn nonce_of(frame: &LanFrame) -> [u8; 32] {
        let (LanFrame::PairNonce { nonce } | LanFrame::PairReveal { nonce }) = frame else {
            panic!("{frame:?}");
        };
        id::from_b64(nonce).unwrap().try_into().unwrap()
    }

    fn exchange(now: Instant) -> (Asker, Answerer, String) {
        let h = [7; 32];
        let (mut asker, _) = Asker::start(h, now);
        let (mut answerer, challenge) =
            Answerer::challenge(h, "r1".into(), EXPIRES, now + EXPIRES, now);
        assert_eq!(answerer.until(), now + CHALLENGE_WAIT);
        let step = asker.on_frame(&challenge, now).unwrap();
        let code = answerer.nonce(&nonce_of(&step.send[0])).unwrap();
        let step = asker.on_frame(&answerer.reveal().unwrap(), now).unwrap();
        assert_eq!(step.code.as_ref(), Some(&code));
        assert!(step.send.is_empty() && step.done.is_none());
        (asker, answerer, code)
    }

    fn other_code(code: &str) -> &'static str {
        if code == "000 000" {
            "000 001"
        } else {
            "000 000"
        }
    }

    #[test]
    fn frames_on_the_wire() {
        let rtc = LanFrame::Rtc {
            signal: RtcSignal::Offer {
                sdp: "s".into(),
                ice_restart: true,
            },
        };
        let frames = [
            (
                LanFrame::Hello {
                    v: 1,
                    key: "k".into(),
                    name: "n".into(),
                    os: "o".into(),
                    kind: "d".into(),
                    sig: "s".into(),
                },
                "hello",
            ),
            (LanFrame::Status { trusted: false }, "status"),
            (LanFrame::PairRequest, "pair_request"),
            (
                LanFrame::PairChallenge {
                    request: "r".into(),
                    expires_in_s: 120,
                    commit: "c".into(),
                },
                "pair_challenge",
            ),
            (LanFrame::PairNonce { nonce: "n".into() }, "pair_nonce"),
            (LanFrame::PairReveal { nonce: "n".into() }, "pair_reveal"),
            (LanFrame::PairConfirm, "pair_confirm"),
            (
                LanFrame::PairResult {
                    outcome: WireOutcome::Denied,
                },
                "pair_result",
            ),
            (
                LanFrame::PairRefused {
                    code: RefuseCode::Cooldown,
                    retry_after_s: None,
                },
                "pair_refused",
            ),
            (LanFrame::PairCancel, "pair_cancel"),
            (rtc.clone(), "rtc"),
            (LanFrame::Bye, "bye"),
        ];
        for (frame, t) in frames {
            let json = serde_json::to_value(&frame).unwrap();
            assert_eq!(json["t"], t);
            let back: LanFrame = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(serde_json::to_value(&back).unwrap(), json);
        }
        assert_eq!(
            serde_json::to_string(&rtc).unwrap(),
            r#"{"t":"rtc","signal":{"type":"Offer","payload":{"sdp":"s","ice_restart":true}}}"#
        );
        let newer: LanFrame = serde_json::from_str(r#"{"t":"from_a_newer_peer","x":1}"#).unwrap();
        assert!(matches!(newer, LanFrame::Unknown));
        let not_shown = LanFrame::PairResult {
            outcome: WireOutcome::NotShown,
        };
        let text = serde_json::to_string(&not_shown).unwrap();
        assert_eq!(text, r#"{"t":"pair_result","outcome":"not_shown"}"#);
        assert!(matches!(
            serde_json::from_str(&text).unwrap(),
            LanFrame::PairResult {
                outcome: WireOutcome::NotShown
            }
        ));
        assert!(matches!(
            serde_json::from_str(r#"{"t":"pair_result","outcome":"maybe"}"#).unwrap(),
            LanFrame::PairResult {
                outcome: WireOutcome::Other
            }
        ));
        let busy = LanFrame::PairRefused {
            code: RefuseCode::PairingBusy,
            retry_after_s: Some(60),
        };
        assert_eq!(
            serde_json::to_string(&busy).unwrap(),
            r#"{"t":"pair_refused","code":"pairing_busy","retry_after_s":60}"#
        );
    }

    #[test]
    fn identity_from_the_account_key() {
        let me = Identity::from_private(&id::b64(&[0; 32])).unwrap();
        let public = SigningKey::from_bytes(&[0; 32]).verifying_key().to_bytes();
        assert_eq!(me.key, public);
        assert_eq!(me.id, id::id_of_bytes(&public));
        let (private, key) = nodeinnet_p2p::crypto::generate_ed25519_keypair();
        assert_eq!(id::b64(&Identity::from_private(&private).unwrap().key), key);
        for bad in [
            id::b64(&[0; 31]),
            "not!base64".to_string(),
            STANDARD.encode([0u8; 32]),
        ] {
            assert!(Identity::from_private(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hello_proves_key_role_and_session() {
        let me = identity(1);
        let h = [9; 32];
        let hello = me.hello(&card("Desk\u{202e}top\n"), Role::Initiator, &h);
        let peer = verify_hello(hello.clone(), Role::Initiator, &h).unwrap();
        assert_eq!((peer.id.as_str(), peer.key), (me.id.as_str(), me.key));
        assert_eq!(peer.name, "Desktop");
        assert_eq!(peer.hello().key, id::b64(&me.key));
        assert!(matches!(
            verify_hello(hello.clone(), Role::Responder, &h),
            Err(TunnelError::BadHello)
        ));
        assert!(matches!(
            verify_hello(hello.clone(), Role::Initiator, &[8; 32]),
            Err(TunnelError::BadHello)
        ));
        let LanFrame::Hello {
            name,
            os,
            kind,
            sig,
            ..
        } = hello
        else {
            unreachable!();
        };
        let forged = |v, key: &[u8]| LanFrame::Hello {
            v,
            key: id::b64(key),
            name: name.clone(),
            os: os.clone(),
            kind: kind.clone(),
            sig: sig.clone(),
        };
        assert!(matches!(
            verify_hello(forged(1, &identity(2).key), Role::Initiator, &h),
            Err(TunnelError::BadHello)
        ));
        assert!(matches!(
            verify_hello(forged(2, &me.key), Role::Initiator, &h),
            Err(TunnelError::Protocol("version"))
        ));
        assert!(matches!(
            verify_hello(forged(1, &me.key[..31]), Role::Initiator, &h),
            Err(TunnelError::BadHello)
        ));
        let mut small = [0u8; 32];
        small[0] = 1;
        let mut weak = [0u8; 64];
        weak[0] = 1;
        let small_order = LanFrame::Hello {
            v: 1,
            key: id::b64(&small),
            name: "x".into(),
            os: String::new(),
            kind: String::new(),
            sig: id::b64(&weak),
        };
        assert!(matches!(
            verify_hello(small_order, Role::Initiator, &h),
            Err(TunnelError::BadHello)
        ));
        assert!(matches!(
            verify_hello(LanFrame::Bye, Role::Initiator, &h),
            Err(TunnelError::Protocol("expected hello"))
        ));
    }

    #[tokio::test]
    async fn messages_are_framed_and_capped() {
        let ((mut ar, mut aw), (mut br, mut bw)) = pipe();
        write_message(&mut aw, b"hello").await.unwrap();
        write_message(&mut aw, b"").await.unwrap();
        assert_eq!(read_message(&mut br, 0, 16).await.unwrap(), b"hello");
        assert!(read_message(&mut br, 0, 16).await.unwrap().is_empty());
        write_message(&mut aw, &[7; 17]).await.unwrap();
        let long = read_message(&mut br, 0, 16).await.unwrap_err();
        assert_eq!(long.kind(), io::ErrorKind::InvalidData);
        write_message(&mut bw, b"ab").await.unwrap();
        let short = read_message(&mut ar, 3, 16).await.unwrap_err();
        assert_eq!(short.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn seal_and_open_follow_the_nonces() {
        let (a, b) = transports().await;
        let (mut sent, mut read) = (0, 0);
        let frames = [
            LanFrame::Status { trusted: true },
            LanFrame::PairConfirm,
            LanFrame::Bye,
        ];
        let sealed: Vec<Vec<u8>> = (frames.iter())
            .map(|frame| seal(&a, &mut sent, frame).unwrap())
            .collect();
        assert_eq!(sent, 3);
        assert!(matches!(
            open(&b, &mut read, &sealed[0]).unwrap(),
            LanFrame::Status { trusted: true }
        ));
        assert!(matches!(
            open(&b, &mut read, &sealed[2]),
            Err(TunnelError::Noise)
        ));
        assert_eq!(read, 1);
        assert!(matches!(
            open(&b, &mut read, &sealed[1]).unwrap(),
            LanFrame::PairConfirm
        ));
        assert!(matches!(
            open(&b, &mut read, &sealed[2]).unwrap(),
            LanFrame::Bye
        ));
        let answer = |n: usize| LanFrame::Rtc {
            signal: RtcSignal::Answer { sdp: "x".repeat(n) },
        };
        let fits = MAX_MESSAGE - TAG - serde_json::to_vec(&answer(0)).unwrap().len();
        let largest = seal(&a, &mut sent, &answer(fits)).unwrap();
        assert_eq!((largest.len(), sent), (MAX_MESSAGE, 4));
        assert!(matches!(
            seal(&a, &mut sent, &answer(fits + 1)),
            Err(TunnelError::TooLarge)
        ));
        assert_eq!(sent, 4);
        assert!(matches!(
            open(&b, &mut read, &largest).unwrap(),
            LanFrame::Rtc { .. }
        ));
    }

    #[tokio::test]
    async fn initiator_and_responder_agree_on_h() {
        let (i, r, mine) = (identity(1), identity(2), card("I"));
        let mut hashes = Vec::new();
        for _ in 0..2 {
            let ((ar, aw), (br, bw)) = pipe();
            let (dialled, answered) =
                tokio::join!(initiate(ar, aw, &i, &mine, &r.id), answer(br, bw, &r, true));
            let (mut dialled, mut answered) = (dialled.unwrap(), answered.unwrap());
            assert!(dialled.trusted && !answered.trusted);
            assert_eq!(
                (dialled.peer.id.as_str(), dialled.peer.name.as_str()),
                (r.id.as_str(), "R")
            );
            assert_eq!(
                (answered.peer.id.as_str(), answered.peer.name.as_str()),
                (i.id.as_str(), "I")
            );
            assert_eq!(dialled.h, answered.h);
            dialled.writer.send(&LanFrame::PairConfirm).await.unwrap();
            assert!(matches!(
                answered.reader.next().await.unwrap(),
                LanFrame::PairConfirm
            ));
            answered.writer.send(&LanFrame::Bye).await.unwrap();
            assert!(matches!(
                dialled.reader.next().await.unwrap(),
                LanFrame::Bye
            ));
            hashes.push(dialled.h);
        }
        assert_ne!(hashes[0], hashes[1]);
    }

    #[tokio::test]
    async fn a_wrong_id_is_refused_by_the_initiator() {
        let (i, r, mine) = (identity(1), identity(2), card("I"));
        let expected = identity(3).id;
        let ((ar, aw), (br, bw)) = pipe();
        let (dialled, _) = tokio::join!(
            initiate(ar, aw, &i, &mine, &expected),
            answer(br, bw, &r, true)
        );
        assert!(matches!(dialled, Err(TunnelError::WrongId(id)) if id == r.id));
        let ((ar, aw), (br, bw)) = pipe();
        let (dialled, answered) =
            tokio::join!(initiate(ar, aw, &i, &mine, &i.id), answer(br, bw, &i, true));
        assert!(matches!(answered, Err(TunnelError::Protocol("own id"))));
        assert!(dialled.is_err());
    }

    #[tokio::test]
    async fn a_forged_hello_is_refused() {
        let (i, r) = (identity(1), identity(2));
        let ((mut ar, mut aw), (br, bw)) = pipe();
        let forger = async {
            let (h, cipher) = noise(&mut ar, &mut aw, Role::Initiator).await.unwrap();
            let (_reader, mut writer) = halves(&mut ar, &mut aw, cipher);
            let hello = i.hello(&card("I"), Role::Responder, &h);
            writer.send(&hello).await.unwrap();
        };
        let (_, answered) = tokio::join!(forger, respond(br, bw, &r));
        assert!(matches!(answered, Err(TunnelError::BadHello)));
    }

    #[tokio::test]
    async fn another_prologue_fails() {
        let (i, mine, expected) = (identity(1), card("I"), identity(2).id);
        let ((ar, aw), (mut br, mut bw)) = pipe();
        let other = async {
            let params: NoiseParams = PARAMS.parse().unwrap();
            let keypair = Builder::new(params.clone()).generate_keypair().unwrap();
            let mut hs = Builder::new(params)
                .prologue(b"nodeinnet-lan/2")
                .local_private_key(&keypair.private)
                .build_responder()
                .unwrap();
            let (mut out, mut payload) = ([0u8; HANDSHAKE_MAX], [0u8; HANDSHAKE_MAX]);
            let first = read_message(&mut br, 1, HANDSHAKE_MAX).await.unwrap();
            hs.read_message(&first, &mut payload).unwrap();
            let n = hs.write_message(&[], &mut out).unwrap();
            write_message(&mut bw, &out[..n]).await.unwrap();
            let _ = read_message(&mut br, 1, HANDSHAKE_MAX).await;
        };
        let (dialled, _) = tokio::join!(initiate(ar, aw, &i, &mine, &expected), other);
        assert!(matches!(dialled, Err(TunnelError::Noise)));
    }

    #[test]
    fn asker_and_answerer_agree_on_the_code() {
        let now = Instant::now();
        let (asker, answerer, code) = exchange(now);
        let (high, low) = code.split_once(' ').unwrap();
        assert!(high.len() == 3 && low.len() == 3);
        assert!(asker.comparing());
        assert_eq!(asker.until(), now + EXPIRES + RESULT_GRACE);
        assert_eq!(answerer.request(), "r1");
        assert!(!answerer.challenged() && answerer.undecided() && !answerer.remember());
        assert_eq!(answerer.until(), now + EXPIRES);
    }

    #[test]
    fn both_decisions_in_either_order() {
        let now = Instant::now();
        let (mut asker, mut answerer, code) = exchange(now);
        let allowed = answerer.allow(true);
        assert!(allowed.done.is_none());
        assert!(matches!(
            allowed.send[..],
            [LanFrame::PairResult {
                outcome: WireOutcome::Allowed
            }]
        ));
        assert_eq!(answerer.until(), now + EXPIRES + RESULT_GRACE);
        assert!(asker
            .on_frame(&allowed.send[0], now)
            .unwrap()
            .done
            .is_none());
        let confirmed = asker.confirm(&code).unwrap();
        assert!(matches!(confirmed.send[..], [LanFrame::PairConfirm]));
        assert_eq!(confirmed.done, Some(PairOutcome::Allowed));
        assert_eq!(answerer.confirm().unwrap().done, Some(PairOutcome::Allowed));
        assert!(answerer.remember());

        let (mut asker, mut answerer, code) = exchange(now);
        assert!(asker.confirm(&code).unwrap().done.is_none());
        assert!(asker.confirm(&code).unwrap().send.is_empty());
        assert!(answerer.confirm().unwrap().done.is_none());
        let repeat = answerer.confirm().unwrap();
        assert!(repeat.send.is_empty() && repeat.done.is_none());
        let allowed = answerer.allow(false);
        assert_eq!(allowed.done, Some(PairOutcome::Allowed));
        assert!(!answerer.remember());
        let result = asker.on_frame(&allowed.send[0], now).unwrap();
        assert_eq!(result.done, Some(PairOutcome::Allowed));
    }

    #[test]
    fn allow_without_confirmation_writes_nothing() {
        let now = Instant::now();
        let (mut asker, mut answerer, code) = exchange(now);
        let allowed = answerer.allow(true);
        assert!(allowed.done.is_none());
        assert!(asker
            .on_frame(&allowed.send[0], now)
            .unwrap()
            .done
            .is_none());
        assert!(asker.confirm(other_code(&code)).is_none());
        assert!(answerer.allow(true).send.is_empty());
        assert_eq!(asker.timed_out(), PairOutcome::Expired);
        let ended = answerer.end(WireOutcome::Expired);
        assert_eq!(ended.done, Some(PairOutcome::Expired));
        let heard = asker.on_frame(&ended.send[0], now).unwrap();
        assert_eq!(heard.done, Some(PairOutcome::Expired));
    }

    #[test]
    fn the_asker_gets_the_code_only_from_the_reveal() {
        let now = Instant::now();
        let h = [7; 32];
        let (mut asker, request) = Asker::start(h, now);
        assert!(matches!(request, LanFrame::PairRequest));
        let (mut answerer, challenge) =
            Answerer::challenge(h, "r".into(), EXPIRES, now + EXPIRES, now);
        assert!(answerer.reveal().is_none());
        let step = asker.on_frame(&challenge, now).unwrap();
        assert!(matches!(step.send[..], [LanFrame::PairNonce { .. }]));
        assert!(step.code.is_none() && step.done.is_none());
        assert!(asker.challenged() && !asker.comparing());
        assert_eq!(asker.until(), now + CHALLENGE_WAIT);
        for frame in [
            challenge.clone(),
            LanFrame::PairResult {
                outcome: WireOutcome::Allowed,
            },
            LanFrame::PairConfirm,
        ] {
            assert!(asker.on_frame(&frame, now).is_none(), "{frame:?}");
        }

        let code = answerer.nonce(&nonce_of(&step.send[0])).unwrap();
        assert!(answerer.undecided() && !answerer.challenged());
        assert!(asker.confirm(&code).is_none());
        let reveal = answerer.reveal().unwrap();
        assert!(answerer.reveal().is_none());
        let opened = sas::Initiator::new(h, commit_of(&challenge)).code(&nonce_of(&reveal));
        assert!(opened.is_some());
        let step = asker.on_frame(&reveal, now).unwrap();
        assert_eq!(step.code, Some(code.clone()));
        assert!(step.send.is_empty() && step.done.is_none());
        assert!(asker.comparing());
        assert!(asker.confirm(&code).is_some());
    }

    #[test]
    fn a_reveal_that_does_not_open_the_commit_is_refused() {
        let now = Instant::now();
        let h = [7; 32];
        let failed = Some(PairOutcome::Failed(
            "the device's code did not check out".into(),
        ));
        let (mut asker, _) = Asker::start(h, now);
        let (mut answerer, challenge) =
            Answerer::challenge(h, "r".into(), EXPIRES, now + EXPIRES, now);
        let step = asker.on_frame(&challenge, now).unwrap();
        answerer.nonce(&nonce_of(&step.send[0])).unwrap();
        let reveal = answerer.reveal().unwrap();
        let mut wrong = nonce_of(&reveal);
        wrong[0] ^= 1;
        let forged = LanFrame::PairReveal {
            nonce: id::b64(&wrong),
        };
        let step = asker.on_frame(&forged, now).unwrap();
        assert_eq!(step.done, failed);
        assert!(step.code.is_none() && step.send.is_empty());
        assert_eq!(asker.on_frame(&reveal, now).unwrap().done, failed);

        let (mut asker, _) = Asker::start(h, now);
        asker.on_frame(&challenge, now).unwrap();
        let broken = LanFrame::PairReveal {
            nonce: "AAAA".into(),
        };
        assert_eq!(asker.on_frame(&broken, now).unwrap().done, failed);
    }

    #[test]
    fn a_relayed_session_breaks_the_commit() {
        let now = Instant::now();
        let (mut asker, _) = Asker::start([1; 32], now);
        let (mut answerer, challenge) =
            Answerer::challenge([2; 32], "r".into(), EXPIRES, now + EXPIRES, now);
        let step = asker.on_frame(&challenge, now).unwrap();
        assert!(answerer.nonce(&nonce_of(&step.send[0])).is_some());
        let step = asker.on_frame(&answerer.reveal().unwrap(), now).unwrap();
        assert_eq!(
            step.done,
            Some(PairOutcome::Failed(
                "the device's code did not check out".into()
            ))
        );
        assert!(step.code.is_none());
    }

    #[test]
    fn endings_reach_the_asker() {
        let now = Instant::now();
        let refused = |retry_after_s| LanFrame::PairRefused {
            code: RefuseCode::Cooldown,
            retry_after_s,
        };
        let (mut requested, _) = Asker::start([1; 32], now);
        assert_eq!(requested.until(), now + CHALLENGE_WAIT);
        assert_eq!(
            requested.timed_out(),
            PairOutcome::Failed("no answer in time".into())
        );
        assert_eq!(
            requested
                .on_frame(&refused(Some(u64::MAX)), now)
                .unwrap()
                .done,
            Some(PairOutcome::Refused {
                code: RefuseCode::Cooldown,
                retry_after: Some(RETRY_MAX)
            })
        );
        let (mut comparing, _, _) = exchange(now);
        assert_eq!(
            comparing.on_frame(&refused(Some(30)), now).unwrap().done,
            Some(PairOutcome::Refused {
                code: RefuseCode::Cooldown,
                retry_after: Some(Duration::from_secs(30))
            })
        );
        let (_, challenge) = Answerer::challenge([1; 32], "r".into(), EXPIRES, now + EXPIRES, now);
        for (outcome, done) in [
            (WireOutcome::Denied, PairOutcome::Denied),
            (WireOutcome::Expired, PairOutcome::Expired),
            (WireOutcome::NotShown, PairOutcome::NotShown),
            (
                WireOutcome::Other,
                PairOutcome::Failed("unknown answer".into()),
            ),
        ] {
            let (mut asker, _, _) = exchange(now);
            let step = asker
                .on_frame(&LanFrame::PairResult { outcome }, now)
                .unwrap();
            assert_eq!(step.done, Some(done.clone()));
            let (mut challenged, _) = Asker::start([1; 32], now);
            challenged.on_frame(&challenge, now).unwrap();
            let step = challenged
                .on_frame(&LanFrame::PairResult { outcome }, now)
                .unwrap();
            assert_eq!(step.done, Some(done));
        }
        let (mut asker, _) = Asker::start([1; 32], now);
        let broken = LanFrame::PairChallenge {
            request: "r".into(),
            expires_in_s: 120,
            commit: "AAAA".into(),
        };
        assert_eq!(
            asker.on_frame(&broken, now).unwrap().done,
            Some(PairOutcome::Failed("broken challenge".into()))
        );
        let (mut asker, _) = Asker::start([1; 32], now);
        let (mut answerer, mut challenge) =
            Answerer::challenge([1; 32], "r".into(), EXPIRES, now + EXPIRES, now);
        if let LanFrame::PairChallenge { expires_in_s, .. } = &mut challenge {
            *expires_in_s = u64::MAX;
        }
        let step = asker.on_frame(&challenge, now).unwrap();
        assert_eq!(
            asker.timed_out(),
            PairOutcome::Failed("no answer in time".into())
        );
        answerer.nonce(&nonce_of(&step.send[0])).unwrap();
        asker.on_frame(&answerer.reveal().unwrap(), now).unwrap();
        assert_eq!(asker.until(), now + EXPIRES_MAX + RESULT_GRACE);
    }

    #[test]
    fn frames_that_do_not_fit_return_none() {
        let now = Instant::now();
        let (mut requested, request) = Asker::start([1; 32], now);
        let reveal = LanFrame::PairReveal {
            nonce: id::b64(&[0; 32]),
        };
        for frame in [
            LanFrame::PairResult {
                outcome: WireOutcome::Denied,
            },
            reveal.clone(),
            LanFrame::PairConfirm,
            LanFrame::Bye,
            request,
        ] {
            assert!(requested.on_frame(&frame, now).is_none(), "{frame:?}");
        }
        assert!(requested.confirm("123 456").is_none());
        let (mut asker, mut answerer, code) = exchange(now);
        let (_, challenge) = Answerer::challenge([1; 32], "x".into(), EXPIRES, now + EXPIRES, now);
        assert!(asker.on_frame(&challenge, now).is_none());
        assert!(asker.on_frame(&reveal, now).is_none());
        assert!(asker.confirm(other_code(&code)).is_none());
        assert!(answerer.nonce(&[0; 32]).is_none());
        assert!(answerer.reveal().is_none());
        let (mut challenged, _) =
            Answerer::challenge([1; 32], "y".into(), EXPIRES, now + EXPIRES, now);
        assert!(challenged.reveal().is_none());
        assert!(challenged.confirm().is_none());
        assert!(challenged.allow(true).send.is_empty());
        assert!(challenged.challenged() && !challenged.undecided());
    }

    #[test]
    fn slots_cap_unadmitted_tunnels() {
        let slots = Arc::new(Slots::default());
        let ip = |last: u8| IpAddr::from([10, 0, 0, last]);
        let mut held: Vec<Slot> = (0..PER_IP_MAX)
            .map(|_| slots.take(ip(1), false).unwrap())
            .collect();
        assert!(slots.take(ip(1), false).is_none());
        assert!(slots.take(ip(1), true).is_none());
        for last in 2..=4 {
            for _ in 0..PER_IP_MAX {
                held.push(slots.take(ip(last), false).unwrap());
            }
        }
        assert_eq!(held.len(), UNADMITTED_MAX);
        assert!(slots.take(ip(5), false).is_none());
        let mut reserved: Vec<Slot> = (0..RESERVED_PER_IP)
            .map(|_| slots.take(ip(6), true).unwrap())
            .collect();
        assert!(slots.take(ip(6), true).is_none());
        for last in 7..=9 {
            for _ in 0..RESERVED_PER_IP {
                reserved.push(slots.take(ip(last), true).unwrap());
            }
        }
        assert_eq!(reserved.len(), RESERVED);
        assert!(reserved.iter().all(|slot| slot.reserved));
        assert!(slots.take(ip(10), true).is_none());
        held.pop();
        assert!(slots.take(ip(5), false).is_some());
        drop(reserved);
        drop(held);
        let held = slots.0.lock().unwrap();
        assert_eq!((held.general, held.reserved, held.per_ip.len()), (0, 0, 0));
        assert!(held.reserved_per_ip.is_empty());
    }
}
