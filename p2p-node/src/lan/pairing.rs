use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub const EXPIRES: Duration = Duration::from_secs(120);
pub const PENDING_MAX: usize = 3;
pub const BUSY_RETRY: Duration = Duration::from_secs(60);
pub const RATE_WINDOW: Duration = Duration::from_secs(60);
pub const RATE_MAX: usize = 3;
pub const RATE_MAX_IP: usize = 6;
pub const COOLDOWN: Duration = Duration::from_secs(10 * 60);
pub const QUIET_WINDOW: Duration = Duration::from_secs(10 * 60);
pub const QUIET_AFTER: usize = 3;
pub const QUIET_AFTER_ALL: usize = 6;
pub const STRIKE_WINDOW: Duration = Duration::from_secs(10 * 60);
pub const STRIKES_MAX: usize = 3;
pub const PAUSE: Duration = Duration::from_secs(10 * 60);
const TRACKED_MAX: usize = 256;

#[derive(Clone, Copy, Debug, Default)]
pub struct Context {
    pub visible: bool,
    pub test_mode: bool,
    pub own: bool,
    pub blocked: bool,
    pub known: bool,
    pub name_clash: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hello {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub os: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Pending,
    Allowed,
    Denied,
    Expired,
    NotShown,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub id: String,
    pub hello: Hello,
    pub addr: IpAddr,
    pub known: bool,
    pub name_clash: bool,
    pub expires: Instant,
    pub shown: Option<Instant>,
    pub quiet: bool,
    pub state: State,
    pub replaces: Option<String>,
    pub code: Option<String>,
}

impl Request {
    pub fn allowable(&self) -> bool {
        self.code.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefuseCode {
    PairingClosed,
    Blocked,
    RateLimited,
    PairingBusy,
    PairingWaiting,
    Cooldown,
    PairingPaused,
    NoName,
    #[serde(other)]
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub code: RefuseCode,
    pub retry_after: Option<Duration>,
}

impl Refused {
    fn new(code: RefuseCode) -> Self {
        Self {
            code,
            retry_after: None,
        }
    }

    fn after(code: RefuseCode, wait: Duration) -> Self {
        Self {
            code,
            retry_after: Some(wait.max(Duration::from_secs(1))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Allow,
    Deny,
    Block,
    NotShown,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Answered {
    Allowed { hello: Hello, addr: IpAddr },
    Denied,
    Blocked { hello: Hello, addr: IpAddr },
    NotShown,
}

#[derive(Default)]
struct Track {
    attempts: VecDeque<Instant>,
    cooldown_until: Option<Instant>,
    unanswered: VecDeque<Instant>,
    used: Option<Instant>,
}

impl Track {
    fn full(&mut self, max: usize, now: Instant) -> Option<Duration> {
        while (self.attempts.front())
            .is_some_and(|&at| now.saturating_duration_since(at) >= RATE_WINDOW)
        {
            self.attempts.pop_front();
        }
        (self.attempts.len() >= max)
            .then(|| RATE_WINDOW.saturating_sub(now.saturating_duration_since(self.attempts[0])))
    }
}

pub struct Pairing {
    expires: Duration,
    requests: Vec<Request>,
    tracks: HashMap<(IpAddr, String), Track>,
    ips: HashMap<IpAddr, Track>,
    strikes: VecDeque<Instant>,
    paused_until: Option<Instant>,
    unanswered: VecDeque<Instant>,
}

impl Default for Pairing {
    fn default() -> Self {
        Self::new(EXPIRES)
    }
}

impl Pairing {
    pub fn new(expires: Duration) -> Self {
        Self {
            expires,
            requests: Vec::new(),
            tracks: HashMap::new(),
            ips: HashMap::new(),
            strikes: VecDeque::new(),
            paused_until: None,
            unanswered: VecDeque::new(),
        }
    }

    pub fn expires(&self) -> Duration {
        self.expires
    }

    /// Run `expire` first.
    pub fn request(
        &mut self,
        hello: Hello,
        addr: IpAddr,
        ctx: Context,
        now: Instant,
    ) -> Result<&Request, Refused> {
        let addr = addr.to_canonical();
        if ctx.own && !ctx.test_mode {
            return Err(Refused::new(RefuseCode::PairingClosed));
        }
        debug_assert_eq!(
            crate::lan::id::id_of(&hello.key).as_deref(),
            Some(hello.id.as_str())
        );
        if ctx.blocked {
            return Err(Refused::new(RefuseCode::Blocked));
        }
        if !ctx.visible {
            return Err(Refused::new(RefuseCode::PairingClosed));
        }
        if let Some(wait) = self.pause_left(now) {
            return Err(Refused::after(RefuseCode::PairingPaused, wait));
        }
        let track = tracked(&mut self.tracks, (addr, hello.id.clone()), now);
        if let Some(wait) = track
            .cooldown_until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|wait| !wait.is_zero())
        {
            return Err(Refused::after(RefuseCode::Cooldown, wait));
        }
        let ip = tracked(&mut self.ips, addr, now);
        let limited = ip
            .full(RATE_MAX_IP, now)
            .or_else(|| track.full(RATE_MAX, now));
        if let Some(wait) = limited {
            return Err(Refused::after(RefuseCode::RateLimited, wait));
        }
        ip.attempts.push_back(now);
        track.attempts.push_back(now);
        let same = (self.requests.iter())
            .position(|r| r.state == State::Pending && r.hello.id == hello.id);
        if let Some(i) = same {
            if self.requests[i].addr != addr {
                return Err(Refused::after(RefuseCode::PairingWaiting, BUSY_RETRY));
            }
        } else if self.all_pending().count() >= PENDING_MAX {
            return Err(Refused::after(RefuseCode::PairingBusy, BUSY_RETRY));
        }
        let replaces = same.map(|i| {
            let old = &mut self.requests[i];
            old.state = State::Expired;
            old.id.clone()
        });
        if let Some(i) = same {
            self.unanswered(i, now);
        }
        let quiet = self.quiet(addr, now);
        self.requests.push(Request {
            id: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()),
            hello,
            addr,
            known: ctx.known,
            name_clash: ctx.name_clash,
            expires: now + self.expires,
            shown: None,
            quiet,
            state: State::Pending,
            replaces,
            code: None,
        });
        Ok(self.requests.last().unwrap())
    }

    pub fn shown(&mut self, request: &str, now: Instant) {
        if let Some(request) = self.requests.iter_mut().find(|r| r.id == request) {
            request.shown.get_or_insert(now);
        }
    }

    pub fn answer(&mut self, request: &str, answer: Answer, now: Instant) -> Option<Answered> {
        let i =
            (self.requests.iter()).position(|r| r.id == request && r.state == State::Pending)?;
        let (addr, id) = (self.requests[i].addr, self.requests[i].hello.id.clone());
        let answered = match answer {
            Answer::Allow => {
                if !self.requests[i].allowable() {
                    return None;
                }
                self.requests[i].state = State::Allowed;
                Answered::Allowed {
                    hello: self.requests[i].hello.clone(),
                    addr,
                }
            }
            Answer::Deny | Answer::Block => {
                self.requests[i].state = State::Denied;
                self.cool_down(addr, &id, now);
                self.strike(now);
                if answer == Answer::Block {
                    Answered::Blocked {
                        hello: self.requests[i].hello.clone(),
                        addr,
                    }
                } else {
                    Answered::Denied
                }
            }
            Answer::NotShown => {
                self.requests[i].state = State::NotShown;
                Answered::NotShown
            }
        };
        Some(answered)
    }

    pub fn expire(&mut self, now: Instant) -> Vec<String> {
        let mut closed = Vec::new();
        let mut expired = Vec::new();
        self.requests.retain_mut(|request| {
            if request.state != State::Pending {
                return false;
            }
            if now >= request.expires {
                request.state = State::Expired;
                closed.push(request.id.clone());
                if request.shown.is_some() {
                    expired.push(request.addr);
                }
            }
            true
        });
        for addr in expired {
            self.count_unanswered(addr, now);
        }
        closed
    }

    pub fn next_expiry(&self) -> Option<Instant> {
        self.all_pending().map(|r| r.expires).min()
    }

    pub fn end_all(&mut self) -> Vec<String> {
        let mut closed = Vec::new();
        for request in &mut self.requests {
            if request.state == State::Pending {
                request.state = State::Expired;
                closed.push(request.id.clone());
            }
        }
        closed
    }

    pub fn cancel(&mut self, request: &str, from: &str, now: Instant) -> Option<bool> {
        let i = self.position(request, from)?;
        if self.requests[i].state != State::Pending {
            self.requests.remove(i);
            return Some(false);
        }
        self.unanswered(i, now);
        self.requests.remove(i);
        Some(true)
    }

    pub fn revealed(&mut self, request: &str, from: &str, code: String) -> Option<&Request> {
        let i = self.position(request, from)?;
        let entry = &mut self.requests[i];
        if entry.state != State::Pending || entry.code.is_some() {
            return None;
        }
        entry.code = Some(code);
        Some(entry)
    }

    pub fn reveal_failed(&mut self, request: &str, from: &str, now: Instant) -> bool {
        let Some(i) = self.position(request, from) else {
            return false;
        };
        if self.requests[i].state != State::Pending || self.requests[i].code.is_some() {
            return false;
        }
        self.requests[i].state = State::Denied;
        self.strike(now);
        true
    }

    pub fn take_not_shown(&mut self, request: &str) -> bool {
        let before = self.requests.len();
        self.requests
            .retain(|r| !(r.id == request && r.state == State::NotShown));
        self.requests.len() != before
    }

    pub fn pending_list(&self) -> impl Iterator<Item = &Request> {
        self.all_pending().filter(|r| r.allowable())
    }

    pub fn pending(&self) -> Option<&Request> {
        self.pending_list().last()
    }

    pub fn get(&self, request: &str) -> Option<&Request> {
        self.requests.iter().find(|r| r.id == request)
    }

    pub fn paused(&self, now: Instant) -> bool {
        self.pause_left(now).is_some()
    }

    pub fn resume(&mut self) {
        self.paused_until = None;
        self.strikes.clear();
        self.unanswered.clear();
        for track in self.tracks.values_mut() {
            track.cooldown_until = None;
        }
        for track in self.ips.values_mut() {
            track.unanswered.clear();
        }
    }

    fn pause_left(&self, now: Instant) -> Option<Duration> {
        self.paused_until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|left| !left.is_zero())
    }

    fn strike(&mut self, now: Instant) -> bool {
        while self
            .strikes
            .front()
            .is_some_and(|&at| now.saturating_duration_since(at) >= STRIKE_WINDOW)
        {
            self.strikes.pop_front();
        }
        self.strikes.push_back(now);
        if self.strikes.len() >= STRIKES_MAX && !self.paused(now) {
            self.paused_until = Some(now + PAUSE);
            self.strikes.clear();
            return true;
        }
        false
    }

    fn unanswered(&mut self, i: usize, now: Instant) {
        if self.requests[i].shown.is_some() {
            self.count_unanswered(self.requests[i].addr, now);
        }
    }

    fn count_unanswered(&mut self, addr: IpAddr, now: Instant) {
        tracked(&mut self.ips, addr, now).unanswered.push_back(now);
        self.unanswered.push_back(now);
    }

    fn quiet(&mut self, addr: IpAddr, now: Instant) -> bool {
        let ip = tracked(&mut self.ips, addr, now);
        recent(&mut ip.unanswered, QUIET_WINDOW, now) >= QUIET_AFTER
            || recent(&mut self.unanswered, QUIET_WINDOW, now) >= QUIET_AFTER_ALL
    }

    fn cool_down(&mut self, addr: IpAddr, id: &str, now: Instant) {
        let key = (addr.to_canonical(), id.to_string());
        tracked(&mut self.tracks, key, now).cooldown_until = Some(now + COOLDOWN);
    }

    fn position(&self, request: &str, from: &str) -> Option<usize> {
        self.requests
            .iter()
            .position(|r| r.id == request && r.hello.id == from)
    }

    fn all_pending(&self) -> impl Iterator<Item = &Request> {
        self.requests.iter().filter(|r| r.state == State::Pending)
    }
}

fn recent(times: &mut VecDeque<Instant>, window: Duration, now: Instant) -> usize {
    while (times.front()).is_some_and(|&at| now.saturating_duration_since(at) >= window) {
        times.pop_front();
    }
    times.len()
}

fn tracked<K: Clone + Eq + Hash>(
    tracks: &mut HashMap<K, Track>,
    key: K,
    now: Instant,
) -> &mut Track {
    if !tracks.contains_key(&key) && tracks.len() >= TRACKED_MAX {
        let oldest = (tracks.iter())
            .min_by_key(|(_, track)| track.used)
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            tracks.remove(&oldest);
        }
    }
    let track = tracks.entry(key).or_default();
    track.used = Some(now);
    track
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lan::id;
    use crate::lan::sas::{Initiator, Responder};

    fn open() -> Context {
        Context {
            visible: true,
            ..Context::default()
        }
    }

    fn lan(last: u8) -> IpAddr {
        IpAddr::from([192, 168, 1, last])
    }

    struct Controller {
        id: String,
        key: String,
    }

    impl Controller {
        fn new() -> Self {
            let key = id::b64(&rand::random::<[u8; 32]>());
            Self {
                id: id::id_of(&key).unwrap(),
                key,
            }
        }

        fn hello(&self) -> Hello {
            Hello {
                id: self.id.clone(),
                name: "Phone".into(),
                kind: "phone".into(),
                os: "android".into(),
                key: self.key.clone(),
            }
        }

        fn id(&self) -> &str {
            &self.id
        }
    }

    fn withdraw(pairing: &mut Pairing, request: &str, now: Instant) -> Option<bool> {
        let from = (pairing.get(request).map(|r| r.hello.id.clone())).unwrap_or_default();
        pairing.cancel(request, &from, now)
    }

    fn reveal(pairing: &mut Pairing, request: &str) {
        let from = (pairing.get(request).map(|r| r.hello.id.clone())).unwrap_or_default();
        pairing.revealed(request, &from, "123 456".into()).unwrap();
    }

    fn code(result: Result<&Request, Refused>) -> RefuseCode {
        result.expect_err("refused").code
    }

    fn ask(pairing: &mut Pairing, c: &Controller, ip: IpAddr, now: Instant) -> String {
        let r = pairing
            .request(c.hello(), ip, open(), now)
            .unwrap()
            .id
            .clone();
        reveal(pairing, &r);
        r
    }

    #[test]
    fn allow_trusts_the_controller_that_asked() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let a = Controller::new();
        let request = pairing.request(a.hello(), lan(20), open(), now).unwrap();
        let (r, expires) = (request.id.clone(), request.expires);
        assert_eq!(r.len(), 22);
        assert_eq!(expires, now + EXPIRES);
        assert!(request.code.is_none() && !request.allowable());
        reveal(&mut pairing, &r);
        let pending = pairing.pending().unwrap();
        assert_eq!(
            (pending.hello.name.as_str(), pending.known),
            ("Phone", false)
        );
        assert_eq!(pairing.next_expiry(), Some(now + Duration::from_secs(120)));
        assert_eq!(pending.addr, lan(20));

        let other = Controller::new();
        assert_eq!(pairing.cancel(&r, other.id(), now), None);
        let Answered::Allowed { hello, addr } = pairing.answer(&r, Answer::Allow, now).unwrap()
        else {
            panic!("not allowed");
        };
        assert_eq!((hello.id.as_str(), addr), (a.id(), lan(20)));
        assert_eq!(hello.key, a.key);
        assert!(pairing.pending().is_none());
        assert_eq!(pairing.get(&r).unwrap().state, State::Allowed);
        pairing.expire(now);
        assert!(pairing.get(&r).is_none());
    }

    #[test]
    fn a_code_must_be_revealed_before_allow() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let a = Controller::new();
        let h = rand::random::<[u8; 32]>();
        let responder = Responder::new(h);
        let initiator = Initiator::new(h, responder.commit());
        let request = pairing.request(a.hello(), lan(20), open(), now).unwrap();
        let r = request.id.clone();
        assert!(request.code.is_none() && !request.allowable());
        assert!(pairing.pending().is_none());
        assert_eq!(pairing.next_expiry(), Some(now + EXPIRES));
        assert_eq!(pairing.answer(&r, Answer::Allow, now), None);
        assert_eq!(pairing.get(&r).unwrap().state, State::Pending);

        let (nonce, on_b) = responder.reveal(&initiator.nonce());
        let on_a = initiator.code(&nonce).unwrap();
        assert!(pairing
            .revealed(&r, Controller::new().id(), on_b.clone())
            .is_none());
        let request = pairing.revealed(&r, a.id(), on_b).unwrap();
        assert_eq!(request.code.as_deref(), Some(on_a.as_str()));
        assert!(request.allowable());
        assert!(pairing.revealed(&r, a.id(), "000 000".into()).is_none());
        assert_eq!(
            pairing.pending().unwrap().code.as_deref(),
            Some(on_a.as_str())
        );
        assert!(matches!(
            pairing.answer(&r, Answer::Allow, now),
            Some(Answered::Allowed { .. })
        ));

        let devices: Vec<Controller> = (0..PENDING_MAX).map(|_| Controller::new()).collect();
        let waiting: Vec<String> = (devices.iter().enumerate())
            .map(|(i, c)| {
                let request = pairing.request(c.hello(), lan(30 + i as u8), open(), now);
                request.unwrap().id.clone()
            })
            .collect();
        assert_eq!(pairing.pending_list().count(), 0);
        assert_eq!(
            code(pairing.request(Controller::new().hello(), lan(40), open(), now)),
            RefuseCode::PairingBusy
        );
        let end = now + EXPIRES;
        assert_eq!(pairing.next_expiry(), Some(end));
        assert_eq!(pairing.expire(end), waiting);
        assert!(pairing
            .revealed(&waiting[0], devices[0].id(), "123 456".into())
            .is_none());
        assert!(pairing.pending().is_none());
    }

    #[test]
    fn a_reveal_that_does_not_open_the_commit_strikes() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let a = Controller::new();
        let r = (pairing.request(a.hello(), lan(20), open(), now).unwrap().id).clone();
        assert!(!pairing.reveal_failed(&r, Controller::new().id(), now));
        assert!(pairing.reveal_failed(&r, a.id(), now));
        assert_eq!(pairing.get(&r).unwrap().state, State::Denied);
        assert!(!pairing.reveal_failed(&r, a.id(), now));
        assert!(pairing.revealed(&r, a.id(), "123 456".into()).is_none());
        assert_eq!(pairing.answer(&r, Answer::Allow, now), None);
        assert!(!pairing.paused(now));

        let r = ask(&mut pairing, &a, lan(20), now);
        assert!(!pairing.reveal_failed(&r, a.id(), now));
        assert_eq!(pairing.get(&r).unwrap().state, State::Pending);
        for i in 1..STRIKES_MAX {
            let c = Controller::new();
            let request = pairing.request(c.hello(), lan(30 + i as u8), open(), now);
            let r = request.unwrap().id.clone();
            assert!(pairing.reveal_failed(&r, c.id(), now));
        }
        assert!(pairing.paused(now));
    }

    #[test]
    fn checks_in_order() {
        let now = Instant::now();
        let a = Controller::new();
        let mut pairing = Pairing::default();
        let own = Context {
            own: true,
            ..open()
        };
        assert_eq!(
            code(pairing.request(a.hello(), lan(10), own, now)),
            RefuseCode::PairingClosed
        );
        let test = Context {
            test_mode: true,
            ..own
        };
        let r = pairing
            .request(a.hello(), lan(10), test, now)
            .unwrap()
            .id
            .clone();
        assert!(withdraw(&mut pairing, &r, now).unwrap());

        let blocked = Context {
            blocked: true,
            ..open()
        };
        assert_eq!(
            code(pairing.request(a.hello(), lan(20), blocked, now)),
            RefuseCode::Blocked
        );
        assert_eq!(
            code(pairing.request(a.hello(), lan(20), Context::default(), now)),
            RefuseCode::PairingClosed
        );
        // Refused before the counters: none of the above used up a request of lan(20).
        for _ in 0..RATE_MAX {
            ask(&mut pairing, &a, lan(20), now);
        }
    }

    #[test]
    fn an_unanswered_request_waits_and_expiry_is_no_deny() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let a = Controller::new();
        let r = ask(&mut pairing, &a, lan(20), now);
        pairing.shown(&r, now);
        let mut t = now;
        for _ in 0..5 {
            t += Duration::from_secs(20);
            assert!(pairing.expire(t).is_empty(), "{:?}", t - now);
        }
        assert_eq!(pairing.pending_list().count(), 1);
        assert_eq!(pairing.next_expiry(), Some(t + Duration::from_secs(20)));
        let end = now + EXPIRES;
        assert_eq!(pairing.expire(end), vec![r.clone()]);
        assert!(pairing.pending().is_none());
        assert_eq!(pairing.get(&r).unwrap().state, State::Expired);
        let mut t = end;
        for _ in 0..STRIKES_MAX {
            let r = ask(&mut pairing, &a, lan(20), t);
            pairing.shown(&r, t);
            t += EXPIRES;
            assert_eq!(pairing.expire(t), vec![r]);
            assert!(!pairing.paused(t));
        }
        assert!(pairing.request(a.hello(), lan(20), open(), t).is_ok());
    }

    #[test]
    fn three_wait_at_once_one_per_device() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let devices: Vec<Controller> = (0..4).map(|_| Controller::new()).collect();
        let ids: Vec<String> = (devices.iter().take(PENDING_MAX).enumerate())
            .map(|(i, c)| ask(&mut pairing, c, lan(20 + i as u8), now))
            .collect();
        let busy = pairing
            .request(devices[3].hello(), lan(30), open(), now)
            .unwrap_err();
        assert_eq!(busy.code, RefuseCode::PairingBusy);
        assert_eq!(busy.retry_after, Some(BUSY_RETRY));
        assert_eq!(
            pairing
                .pending_list()
                .map(|r| r.id.clone())
                .collect::<Vec<_>>(),
            ids
        );
        assert_eq!(pairing.pending().unwrap().id, ids[2]);

        let t = now + Duration::from_secs(5);
        let request = pairing.request(devices[0].hello(), lan(20), open(), t);
        let request = request.unwrap();
        let (again, replaced) = (request.id.clone(), request.replaces.clone());
        assert_eq!(replaced.as_deref(), Some(ids[0].as_str()));
        reveal(&mut pairing, &again);
        assert_eq!(pairing.pending_list().count(), PENDING_MAX);
        assert_eq!(pairing.pending().unwrap().id, again);
        assert_eq!(pairing.next_expiry(), Some(now + EXPIRES));
        assert_eq!(pairing.get(&ids[0]).unwrap().state, State::Expired);
        let other = pairing
            .request(devices[0].hello(), lan(40), open(), t)
            .unwrap_err();
        assert_eq!(other.code, RefuseCode::PairingWaiting);
        assert_eq!(other.retry_after, Some(BUSY_RETRY));
        assert_eq!(pairing.pending_list().count(), PENDING_MAX);
        pairing.answer(&ids[1], Answer::Allow, t).unwrap();
        assert!(pairing
            .request(devices[3].hello(), lan(30), open(), t)
            .is_ok());
    }

    #[test]
    fn rate_limits_per_ip_and_id_and_per_ip() {
        let now = Instant::now();
        let a = Controller::new();
        let mut pairing = Pairing::default();
        for _ in 0..RATE_MAX {
            let r = ask(&mut pairing, &a, lan(20), now);
            assert!(withdraw(&mut pairing, &r, now).unwrap());
        }
        let limited = pairing
            .request(a.hello(), lan(20), open(), now)
            .unwrap_err();
        assert_eq!(limited.code, RefuseCode::RateLimited);
        assert_eq!(limited.retry_after, Some(RATE_WINDOW));
        assert!(pairing.request(a.hello(), lan(21), open(), now).is_ok());
        let t = now + Duration::from_secs(1);
        for _ in 0..RATE_MAX_IP - RATE_MAX {
            let r = ask(&mut pairing, &Controller::new(), lan(20), t);
            assert!(withdraw(&mut pairing, &r, t).unwrap());
        }
        let limited = pairing
            .request(Controller::new().hello(), lan(20), open(), t)
            .unwrap_err();
        assert_eq!(limited.code, RefuseCode::RateLimited);
        assert_eq!(
            limited.retry_after,
            Some(RATE_WINDOW - Duration::from_secs(1))
        );
        assert!(pairing
            .request(Controller::new().hello(), lan(22), open(), t)
            .is_ok());
        let later = now + EXPIRES;
        assert_eq!(pairing.expire(later).len(), 1);
        assert!(pairing.request(a.hello(), lan(20), open(), later).is_ok());
    }

    #[test]
    fn denials_strike_and_withdrawals_do_not() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let (a, b, c, d) = (
            Controller::new(),
            Controller::new(),
            Controller::new(),
            Controller::new(),
        );

        let r = ask(&mut pairing, &a, lan(20), now);
        let first = r.clone();
        assert_eq!(
            pairing.answer(&r, Answer::Deny, now).unwrap(),
            Answered::Denied
        );
        assert_eq!(pairing.get(&r).unwrap().state, State::Denied);
        let cooling = pairing
            .request(a.hello(), lan(20), open(), now)
            .unwrap_err();
        assert_eq!(cooling.code, RefuseCode::Cooldown);
        assert_eq!(cooling.retry_after, Some(COOLDOWN));

        let t = now + Duration::from_secs(1);
        for _ in 0..STRIKES_MAX {
            let r = ask(&mut pairing, &b, lan(21), t);
            pairing.shown(&r, t);
            assert!(withdraw(&mut pairing, &r, t).unwrap());
        }
        assert!(!pairing.paused(t));

        for (c, ip) in [(&c, lan(30)), (&d, lan(31))] {
            let r = ask(&mut pairing, c, ip, t);
            pairing.answer(&r, Answer::Deny, t).unwrap();
        }
        assert!(pairing.paused(t));
        let paused = pairing
            .request(Controller::new().hello(), lan(40), open(), t)
            .unwrap_err();
        assert_eq!(paused.code, RefuseCode::PairingPaused);
        assert_eq!(paused.retry_after, Some(PAUSE));

        let later = t + PAUSE;
        assert!(!pairing.paused(later));
        assert!(pairing.request(d.hello(), lan(40), open(), later).is_ok());
        assert!(pairing.get(&first).is_some());
        pairing.expire(later);
        assert!(pairing.get(&first).is_none());
    }

    #[test]
    fn an_address_that_leaves_prompts_unanswered_goes_quiet() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let (a, b) = (Controller::new(), Controller::new());
        let r = ask(&mut pairing, &a, lan(20), now);
        assert!(!pairing.get(&r).unwrap().quiet);
        pairing.shown(&r, now);
        assert!(withdraw(&mut pairing, &r, now).unwrap());
        let r = ask(&mut pairing, &a, lan(20), now);
        pairing.shown(&r, now);
        let again = pairing.request(a.hello(), lan(20), open(), now).unwrap();
        let (again, quiet) = (again.id.clone(), again.quiet);
        assert!(!quiet);
        pairing.shown(&again, now);
        let t = now + Duration::from_secs(1);
        let unseen = ask(&mut pairing, &b, lan(20), t);
        assert!(withdraw(&mut pairing, &unseen, t).unwrap());
        let t = now + EXPIRES;
        assert_eq!(pairing.expire(t), vec![again]);

        let r = ask(&mut pairing, &b, lan(20), t);
        assert!(pairing.get(&r).unwrap().quiet);
        assert!(pairing.pending().unwrap().quiet);
        assert!(matches!(
            pairing.answer(&r, Answer::Allow, t),
            Some(Answered::Allowed { .. })
        ));
        let other = ask(&mut pairing, &a, lan(21), t);
        assert!(!pairing.get(&other).unwrap().quiet);
        assert!(!pairing.paused(t));
        let later = t + QUIET_WINDOW;
        pairing.expire(later);
        let r = ask(&mut pairing, &a, lan(20), later);
        assert!(!pairing.get(&r).unwrap().quiet);
        let mut pairing = Pairing::default();
        for i in 0..QUIET_AFTER {
            let r = ask(&mut pairing, &Controller::new(), lan(20), now);
            pairing.shown(&r, now);
            withdraw(&mut pairing, &r, now).unwrap();
            assert_eq!(pairing.ips[&lan(20)].unanswered.len(), i + 1);
        }
        pairing.resume();
        let r = ask(&mut pairing, &a, lan(20), now);
        assert!(!pairing.get(&r).unwrap().quiet);
    }

    #[test]
    fn prompts_unanswered_from_many_addresses_quiet_everyone() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        for i in 0..QUIET_AFTER_ALL {
            let ip = lan(20 + (i / 2) as u8);
            let r = ask(&mut pairing, &Controller::new(), ip, now);
            assert!(!pairing.get(&r).unwrap().quiet, "{i}");
            pairing.shown(&r, now);
            withdraw(&mut pairing, &r, now).unwrap();
        }
        let r = ask(&mut pairing, &Controller::new(), lan(99), now);
        assert!(pairing.get(&r).unwrap().quiet);
        let mut pairing = Pairing::default();
        let a = Controller::new();
        let mut t = now;
        for _ in 0..QUIET_AFTER {
            let r = ask(&mut pairing, &a, lan(20), t);
            pairing.shown(&r, t);
            t += EXPIRES;
            assert_eq!(pairing.expire(t), vec![r]);
        }
        let r = ask(&mut pairing, &a, lan(20), t);
        assert!(pairing.get(&r).unwrap().quiet);
    }

    #[test]
    fn closing_pairing_ends_every_request() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let (a, b) = (Controller::new(), Controller::new());
        let ra = ask(&mut pairing, &a, lan(20), now);
        let rb = ask(&mut pairing, &b, lan(21), now);
        pairing.shown(&ra, now);
        assert_eq!(pairing.end_all(), vec![ra.clone(), rb]);
        assert!(pairing.pending().is_none());
        assert_eq!(pairing.next_expiry(), None);
        assert_eq!(pairing.get(&ra).unwrap().state, State::Expired);
        assert!(!pairing.paused(now));
        assert!(pairing.request(a.hello(), lan(20), open(), now).is_ok());
    }

    #[test]
    fn strikes_out_of_the_window_do_not_count() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        for (i, at) in [0, 5 * 60, 11 * 60].into_iter().enumerate() {
            let at = now + Duration::from_secs(at);
            let r = ask(&mut pairing, &Controller::new(), lan(i as u8 + 1), at);
            pairing.answer(&r, Answer::Deny, at).unwrap();
        }
        assert!(!pairing.paused(now + Duration::from_secs(11 * 60)));
    }

    #[test]
    fn resume_lifts_the_pause() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let a = Controller::new();
        for i in 0..STRIKES_MAX {
            let r = ask(&mut pairing, &Controller::new(), lan(i as u8 + 1), now);
            pairing.answer(&r, Answer::Deny, now).unwrap();
        }
        assert!(pairing.paused(now));
        let r = pairing.request(a.hello(), lan(1), open(), now);
        assert_eq!(code(r), RefuseCode::PairingPaused);
        pairing.resume();
        assert!(!pairing.paused(now));
        assert!(pairing.request(a.hello(), lan(1), open(), now).is_ok());
    }

    #[test]
    fn resume_lets_a_cooling_device_ask_again() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let a = Controller::new();
        let r = ask(&mut pairing, &a, lan(20), now);
        pairing.answer(&r, Answer::Deny, now).unwrap();
        let later = now + Duration::from_secs(60);
        assert_eq!(
            code(pairing.request(a.hello(), lan(20), open(), later)),
            RefuseCode::Cooldown
        );
        pairing.resume();
        assert!(pairing.request(a.hello(), lan(20), open(), later).is_ok());
    }

    #[test]
    fn block_not_shown_and_unknown_answers() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let a = Controller::new();
        let r = ask(&mut pairing, &a, lan(20), now);
        let Answered::Blocked { hello, addr } = pairing.answer(&r, Answer::Block, now).unwrap()
        else {
            panic!("not blocked");
        };
        assert_eq!((hello.id.as_str(), addr), (a.id(), lan(20)));
        assert_eq!(pairing.answer(&r, Answer::Allow, now), None);
        assert_eq!(pairing.answer("nope", Answer::Allow, now), None);

        let b = Controller::new();
        let r = ask(&mut pairing, &b, lan(21), now);
        assert_eq!(
            pairing.answer(&r, Answer::NotShown, now).unwrap(),
            Answered::NotShown
        );
        assert!(!pairing.take_not_shown("nope"));
        assert!(pairing.take_not_shown(&r));
        assert!(pairing.request(b.hello(), lan(21), open(), now).is_ok());
    }

    #[test]
    fn known_and_name_clash_reach_the_request() {
        let now = Instant::now();
        let mut pairing = Pairing::new(Duration::from_secs(45));
        let a = Controller::new();
        let ctx = Context {
            known: true,
            name_clash: true,
            ..open()
        };
        let request = pairing.request(a.hello(), lan(20), ctx, now).unwrap();
        assert!(request.known && request.name_clash);
        assert_eq!(request.expires, now + Duration::from_secs(45));
        let r = request.id.clone();
        reveal(&mut pairing, &r);
        assert!(pairing.pending().unwrap().known);
        pairing.answer(&r, Answer::Allow, now).unwrap();
        assert_eq!(withdraw(&mut pairing, &r, now), Some(false));
        assert_eq!(withdraw(&mut pairing, &r, now), None);
    }

    #[test]
    fn tracks_keep_the_most_recent() {
        let now = Instant::now();
        let mut pairing = Pairing::default();
        let a = Controller::new();
        let r = ask(&mut pairing, &a, lan(20), now);
        pairing.answer(&r, Answer::Deny, now).unwrap();
        for i in 0..TRACKED_MAX {
            let t = now + Duration::from_secs(1 + i as u64);
            let ip = IpAddr::from([10, 0, (i / 250) as u8, (i % 250) as u8 + 1]);
            let _ = pairing.request(Controller::new().hello(), ip, open(), t);
        }
        assert_eq!(pairing.ips.len(), 256);
        assert_eq!(pairing.tracks.len(), TRACKED_MAX);
        assert!(!pairing.ips.contains_key(&lan(20)));
        let later = now + Duration::from_secs(1 + TRACKED_MAX as u64);
        pairing.expire(later);
        assert!(pairing.request(a.hello(), lan(20), open(), later).is_ok());
    }

    #[test]
    fn refuse_codes_on_the_wire() {
        let busy = serde_json::to_string(&RefuseCode::PairingBusy).unwrap();
        assert_eq!(busy, r#""pairing_busy""#);
        assert_eq!(
            serde_json::from_str::<RefuseCode>(&busy).unwrap(),
            RefuseCode::PairingBusy
        );
        assert_eq!(
            serde_json::from_str::<RefuseCode>(r#""from_a_newer_peer""#).unwrap(),
            RefuseCode::Other
        );
    }
}
