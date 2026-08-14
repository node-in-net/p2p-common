use serde::{Deserialize, Serialize};

/// Signaling message types for establishing a WebRTC connection.
/// Uses `serde(tag = "type", content = "payload")` for convenient parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum RtcSignal {
    /// Step 1: the initiator sends an SDP Offer.
    Offer {
        sdp: String,
        /// When true, this is an in-session **ICE restart** offer — the receiver
        /// should renegotiate on the *existing* PeerConnection (preserving the
        /// authenticated session, DataChannel and any media tracks) instead of
        /// rebuilding from scratch. Optional for backward compatibility: peers
        /// that predate this field decode it as `false` and fall back to the
        /// old rebuild path.
        #[serde(default)]
        ice_restart: bool,
    },

    /// Step 2: the receiver replies with an SDP Answer.
    Answer { sdp: String },

    /// Step 3: both sides exchange ICE candidates.
    IceCandidate {
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    },
}

/// Client-to-server message relaying an RTC signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtcSignalEnvelope {
    /// Session (device) ID the signal is addressed to.
    pub to_node_id: String,
    /// The signaling message itself.
    pub signal: RtcSignal,
}

/// Server-to-client message carrying an RTC signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundRtcSignal {
    /// Session (device) ID the signal came from.
    pub from_node_id: String,
    /// The signaling message itself.
    pub signal: RtcSignal,
}

/// Credentials and address list for connecting to a TURN server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnCredentials {
    pub username: String,
    pub credential: String,
    pub uris: Vec<String>,
}

pub fn get_turn_credentials(
    login: &str,
    secret: &str,
    is_premium: bool,
) -> Option<TurnCredentials> {
    if is_premium {
        // 24 hours validity for the TURN credentials
        let timestamp = (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp();
        let turn_username = format!("{}:{}", timestamp, login);

        use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        type HmacSha1 = Hmac<Sha1>;

        let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).ok()?;
        mac.update(turn_username.as_bytes());
        let turn_password = b64.encode(mac.finalize().into_bytes());

        let turn_servers_env = std::env::var("TURN_SERVERS").unwrap_or_default();
        let uris = if !turn_servers_env.trim().is_empty() {
            turn_servers_env
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        } else {
            vec![
                "turn:eu.node.in.net:3478".to_string(),
                "turn:us.node.in.net:3478".to_string(),
                "turns:eu.node.in.net:443?transport=tcp".to_string(),
                "turns:us.node.in.net:443?transport=tcp".to_string(),
            ]
        };

        Some(TurnCredentials {
            username: turn_username,
            credential: turn_password,
            uris,
        })
    } else {
        Some(TurnCredentials {
            username: "".to_string(),
            credential: "".to_string(),
            uris: vec!["stun:stun.l.google.com:19302".to_string()],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_premium_returns_stun_only() {
        let creds = get_turn_credentials("user", "secret", false).unwrap();
        assert_eq!(creds.username, "");
        assert_eq!(creds.credential, "");
        assert_eq!(creds.uris.len(), 1);
        assert!(creds.uris[0].starts_with("stun:"), "uri: {}", creds.uris[0]);
    }

    #[test]
    fn premium_returns_turn_credentials_with_login() {
        let creds = get_turn_credentials("alice", "topsecret", true).unwrap();
        assert!(
            creds.username.contains("alice"),
            "username should contain login: {}",
            creds.username
        );
        assert!(
            !creds.credential.is_empty(),
            "credential should not be empty"
        );
        assert!(!creds.uris.is_empty(), "uris should not be empty");
        assert!(
            creds.uris.iter().any(|u| u.starts_with("turn:")),
            "should have at least one turn: uri"
        );
    }

    #[test]
    fn premium_username_format_is_timestamp_colon_login() {
        let creds = get_turn_credentials("bob", "secret", true).unwrap();
        let parts: Vec<&str> = creds.username.splitn(2, ':').collect();
        assert_eq!(parts.len(), 2, "username should be <ts>:<login>");
        assert_eq!(parts[1], "bob");
        let ts: i64 = parts[0].parse().expect("first part should be a timestamp");
        assert!(ts > 0, "timestamp should be positive");
    }

    #[test]
    fn rtc_signal_offer_roundtrips_json() {
        let signal = RtcSignal::Offer {
            sdp: "v=0\r\n".to_string(),
            ice_restart: false,
        };
        let json = serde_json::to_string(&signal).unwrap();
        let parsed: RtcSignal = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, RtcSignal::Offer { sdp, .. } if sdp == "v=0\r\n"));
    }

    #[test]
    fn rtc_signal_offer_without_ice_restart_field_defaults_false() {
        // A payload sent by an older peer (no `ice_restart` key) must decode.
        let json = r#"{"type":"Offer","payload":{"sdp":"v=0\r\n"}}"#;
        let parsed: RtcSignal = serde_json::from_str(json).unwrap();
        assert!(matches!(
            parsed,
            RtcSignal::Offer {
                ice_restart: false,
                ..
            }
        ));
    }
}
