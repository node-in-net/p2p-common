#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    WebSocketConnecting,
    WebSocketConnected,
    LocalMeshFallback,
}

#[derive(Debug, Clone)]
pub struct PeerBackoff {
    pub attempt_count: usize,
    pub last_attempt: std::time::Instant,
    pub is_connected: bool,
}

pub fn get_cooldown_duration(attempt_count: usize) -> std::time::Duration {
    crate::limits::timeouts().redial_backoff(attempt_count)
}

pub fn peer_slot_available(
    active: &std::collections::HashMap<String, crate::rtc::WebRtcClient>,
    peer_id: &str,
) -> bool {
    use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as S;
    let max = crate::limits::max_peers() as usize;
    if max == 0 || active.contains_key(peer_id) {
        return true;
    }
    let taken = active
        .values()
        .filter(|p| {
            matches!(
                p.peer_connection.connection_state(),
                S::Connected | S::New | S::Connecting
            )
        })
        .count();
    taken < max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_attempt_has_zero_cooldown() {
        assert_eq!(get_cooldown_duration(0).as_secs(), 0);
    }

    #[test]
    fn cooldown_increases_with_attempts() {
        let d1 = get_cooldown_duration(1);
        let d2 = get_cooldown_duration(2);
        let d3 = get_cooldown_duration(3);
        assert!(
            d1 < d2 && d2 < d3,
            "cooldowns should increase: {:?} < {:?} < {:?}",
            d1,
            d2,
            d3
        );
    }

    #[test]
    fn attempt_5_is_60_seconds() {
        assert_eq!(get_cooldown_duration(5).as_secs(), 60);
    }

    #[test]
    fn high_attempt_count_caps_at_120_seconds() {
        assert_eq!(get_cooldown_duration(6).as_secs(), 120);
        assert_eq!(get_cooldown_duration(100).as_secs(), 120);
    }

    #[test]
    fn network_mode_equality() {
        assert_eq!(
            NetworkMode::WebSocketConnected,
            NetworkMode::WebSocketConnected
        );
        assert_ne!(
            NetworkMode::WebSocketConnecting,
            NetworkMode::LocalMeshFallback
        );
    }
}
