use std::sync::atomic::{AtomicU32, Ordering};

static MAX_PEERS: AtomicU32 = AtomicU32::new(0);

pub fn set_max_peers(n: u32) {
    MAX_PEERS.store(n, Ordering::Relaxed);
}

pub fn max_peers() -> u32 {
    MAX_PEERS.load(Ordering::Relaxed)
}

static BANDWIDTH_KBPS: AtomicU32 = AtomicU32::new(0);

pub const MIN_KBPS: u32 = 16;

pub const QUEUE_SECONDS: u64 = 2;
pub const DEFAULT_QUEUE_SLOTS: usize = 1024;
pub const MIN_QUEUE_SLOTS: usize = 8;

pub fn set_bandwidth_limit_kbps(kbps: u32) {
    BANDWIDTH_KBPS.store(effective_kbps(kbps), Ordering::Relaxed);
}

pub fn effective_kbps(requested: u32) -> u32 {
    if requested == 0 {
        0
    } else {
        requested.max(MIN_KBPS)
    }
}

pub fn bandwidth_limit_kbps() -> u32 {
    BANDWIDTH_KBPS.load(Ordering::Relaxed)
}

pub fn outbound_queue_slots(item_bytes: usize) -> usize {
    queue_slots_for(bandwidth_limit_kbps(), item_bytes)
}

pub fn queue_slots_for(kbps: u32, item_bytes: usize) -> usize {
    if kbps == 0 {
        return DEFAULT_QUEUE_SLOTS;
    }
    let per_second = u64::from(kbps) * 1024;
    let slots = per_second.saturating_mul(QUEUE_SECONDS) / item_bytes.max(1) as u64;
    slots.clamp(MIN_QUEUE_SLOTS as u64, DEFAULT_QUEUE_SLOTS as u64) as usize
}

pub fn is_bulk_stream(msg: &nodeinnet_p2p::P2pMessage) -> bool {
    matches!(
        msg,
        nodeinnet_p2p::P2pMessage::FileChunk { .. }
            | nodeinnet_p2p::P2pMessage::HttpResponseChunk { .. }
    )
}

struct Bucket {
    tokens: f64,
    last: std::time::Instant,
}

fn bucket() -> &'static tokio::sync::Mutex<Bucket> {
    static BUCKET: std::sync::OnceLock<tokio::sync::Mutex<Bucket>> = std::sync::OnceLock::new();
    BUCKET.get_or_init(|| {
        tokio::sync::Mutex::new(Bucket {
            tokens: 0.0,
            last: std::time::Instant::now(),
        })
    })
}

pub(crate) async fn acquire_send_tokens(bytes: usize) {
    let kbps = bandwidth_limit_kbps();
    if kbps == 0 {
        return;
    }
    let rate = f64::from(kbps) * 1024.0;

    let wait = {
        let mut b = bucket().lock().await;
        let now = std::time::Instant::now();
        b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * rate).min(rate);
        b.last = now;
        b.tokens -= bytes as f64;
        if b.tokens < 0.0 {
            Some(std::time::Duration::from_secs_f64(-b.tokens / rate))
        } else {
            None
        }
    };

    if let Some(d) = wait {
        tokio::time::sleep(d).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub ping_interval_secs: u64,
    pub pong_timeout_ms: u64,
    pub ws_connect_secs: u64,
    pub dial_stuck_secs: [u64; 6],
    pub redial_backoff_secs: [u64; 7],
    pub ice_recovery_grace_secs: u64,
    pub ice_signaling_stable_secs: u64,
    pub ice_teardown_secs: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            ping_interval_secs: 15,
            pong_timeout_ms: 45_000,
            ws_connect_secs: 5,
            dial_stuck_secs: [3, 3, 5, 15, 30, 60],
            redial_backoff_secs: [0, 5, 10, 15, 30, 60, 120],
            ice_recovery_grace_secs: 3,
            ice_signaling_stable_secs: 5,
            ice_teardown_secs: 12,
        }
    }
}

impl Timeouts {
    fn sanitised(mut self) -> Self {
        self.ping_interval_secs = self.ping_interval_secs.clamp(1, 3600);
        let floor_ms = self.ping_interval_secs.saturating_mul(3_000);
        self.pong_timeout_ms = self.pong_timeout_ms.clamp(floor_ms, 24 * 3600 * 1000);
        self.ws_connect_secs = self.ws_connect_secs.clamp(1, 3600);
        for v in &mut self.dial_stuck_secs {
            *v = (*v).clamp(1, 3600);
        }
        for v in &mut self.redial_backoff_secs {
            *v = (*v).min(3600);
        }
        self.ice_recovery_grace_secs = self.ice_recovery_grace_secs.clamp(1, 600);
        self.ice_signaling_stable_secs = self.ice_signaling_stable_secs.clamp(1, 600);
        self.ice_teardown_secs = self.ice_teardown_secs.clamp(1, 3600);
        self
    }

    pub fn redial_backoff(&self, attempt: usize) -> std::time::Duration {
        let idx = attempt.min(self.redial_backoff_secs.len() - 1);
        std::time::Duration::from_secs(self.redial_backoff_secs[idx])
    }

    pub fn dial_stuck(&self, attempt: usize) -> std::time::Duration {
        let idx = attempt.min(self.dial_stuck_secs.len() - 1);
        std::time::Duration::from_secs(self.dial_stuck_secs[idx])
    }
}

static TIMEOUTS: std::sync::OnceLock<std::sync::RwLock<Timeouts>> = std::sync::OnceLock::new();

fn timeouts_cell() -> &'static std::sync::RwLock<Timeouts> {
    TIMEOUTS.get_or_init(|| std::sync::RwLock::new(Timeouts::default()))
}

pub fn set_timeouts(t: Timeouts) {
    if let Ok(mut slot) = timeouts_cell().write() {
        *slot = t.sanitised();
    }
}

pub fn timeouts() -> Timeouts {
    timeouts_cell().read().map(|t| *t).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_zero_rate_is_raised_to_the_floor_and_zero_stays_unlimited() {
        assert_eq!(effective_kbps(0), 0);
        assert_eq!(effective_kbps(1), MIN_KBPS);
        assert_eq!(effective_kbps(MIN_KBPS - 1), MIN_KBPS);
        assert_eq!(effective_kbps(512), 512);
    }

    #[test]
    fn queue_depth_scales_with_the_rate_instead_of_collapsing_to_a_floor() {
        const CHUNK: usize = 16 * 1024;
        assert_eq!(
            queue_slots_for(0, CHUNK),
            DEFAULT_QUEUE_SLOTS,
            "unlimited is unchanged"
        );
        assert_eq!(queue_slots_for(1024, CHUNK), 128, "1 MiB/s x 2 s / 16 KiB");
        assert_eq!(
            queue_slots_for(2048, CHUNK),
            256,
            "twice the rate, twice the queue"
        );
        assert_eq!(
            queue_slots_for(64 * 1024, CHUNK),
            DEFAULT_QUEUE_SLOTS,
            "capped at the historical depth"
        );
        assert_eq!(
            queue_slots_for(MIN_KBPS, CHUNK),
            MIN_QUEUE_SLOTS,
            "never below the floor"
        );
    }

    #[test]
    fn between_the_clamps_every_queue_holds_the_same_number_of_seconds() {
        const CHUNK: usize = 16 * 1024;
        for kbps in [256u32, 512, 1024, 4096] {
            let seconds =
                (queue_slots_for(kbps, CHUNK) * CHUNK) as f64 / (f64::from(kbps) * 1024.0);
            assert!(
                (seconds - QUEUE_SECONDS as f64).abs() < 0.5,
                "{kbps} KiB/s buffers {seconds:.2}s, expected about {QUEUE_SECONDS}s"
            );
        }
    }

    #[test]
    fn outside_the_clamps_the_backlog_is_documented_to_differ() {
        const CHUNK: usize = 16 * 1024;
        let seconds =
            (queue_slots_for(MIN_KBPS, CHUNK) * CHUNK) as f64 / (f64::from(MIN_KBPS) * 1024.0);
        assert!(
            seconds > QUEUE_SECONDS as f64,
            "at the floor the backlog is longer"
        );
        assert_eq!(seconds, 8.0);
    }

    #[test]
    fn the_default_timeouts_reproduce_the_previous_hardcoded_ladders() {
        let t = Timeouts::default();
        assert_eq!(t.ping_interval_secs, 15);
        assert_eq!(t.pong_timeout_ms, 45_000);
        assert_eq!(t.ws_connect_secs, 5);
        assert_eq!(t.ice_recovery_grace_secs, 3);
        assert_eq!(t.ice_signaling_stable_secs, 5);
        assert_eq!(t.ice_teardown_secs, 12);

        for (attempt, expected) in [
            (0, 0),
            (1, 5),
            (2, 10),
            (3, 15),
            (4, 30),
            (5, 60),
            (6, 120),
            (99, 120),
        ] {
            assert_eq!(
                t.redial_backoff(attempt).as_secs(),
                expected,
                "redial attempt {attempt}"
            );
        }
        for (attempt, expected) in [(0, 3), (1, 3), (2, 5), (3, 15), (4, 30), (5, 60), (99, 60)] {
            assert_eq!(
                t.dial_stuck(attempt).as_secs(),
                expected,
                "dial-stuck attempt {attempt}"
            );
        }
    }

    #[test]
    fn a_pong_timeout_that_would_kill_healthy_sessions_is_raised() {
        let bad = Timeouts {
            ping_interval_secs: 20,
            pong_timeout_ms: 5_000,
            ..Timeouts::default()
        };
        assert_eq!(bad.sanitised().pong_timeout_ms, 60_000);
        let good = Timeouts {
            ping_interval_secs: 10,
            pong_timeout_ms: 90_000,
            ..Timeouts::default()
        };
        assert_eq!(good.sanitised().pong_timeout_ms, 90_000);
        let zero = Timeouts {
            ping_interval_secs: 0,
            ..Timeouts::default()
        };
        assert_eq!(zero.sanitised().ping_interval_secs, 1);
    }

    #[test]
    fn only_the_bulk_streams_are_charged() {
        use nodeinnet_p2p::P2pMessage;
        assert!(is_bulk_stream(&P2pMessage::FileChunk {
            transfer_id: uuid::Uuid::nil(),
            offset: 0,
            data: vec![0; 8],
        }));
        assert!(is_bulk_stream(&P2pMessage::HttpResponseChunk {
            resource_id: "r".into(),
            request_id: uuid::Uuid::nil(),
            chunk: vec![0; 8],
        }));
        assert!(!is_bulk_stream(&P2pMessage::Ping(0)));
        assert!(!is_bulk_stream(&P2pMessage::Pong(0)));
        assert!(!is_bulk_stream(&P2pMessage::TerminalInput {
            resource_id: "r".into(),
            data: vec![0; 8],
        }));
        assert!(!is_bulk_stream(&P2pMessage::SocksData {
            resource_id: "r".into(),
            stream_id: uuid::Uuid::nil(),
            data: vec![0; 8],
        }));
    }

    #[test]
    fn the_setters_reach_the_getters() {
        set_max_peers(0);
        assert_eq!(max_peers(), 0, "the default must mean unlimited");
        set_max_peers(3);
        assert_eq!(max_peers(), 3);
        set_max_peers(0);

        set_bandwidth_limit_kbps(0);
        assert_eq!(bandwidth_limit_kbps(), 0);
        set_bandwidth_limit_kbps(1);
        assert_eq!(
            bandwidth_limit_kbps(),
            MIN_KBPS,
            "the getter reports the rate in force"
        );
        set_bandwidth_limit_kbps(0);
    }
}
