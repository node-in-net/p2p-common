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

/// Relay region picked by the user in the client settings and sent to the
/// server at login and token refresh. Only the server acts on it — the client
/// uses the returned URI list verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TurnRegion {
    /// Every relay we operate.
    #[default]
    Auto,
    Eu,
    Us,
}

/// Central relay embedded in the backend: UDP only. Always offered, whatever
/// the region — ICE also pairs relay against relay, so a peer parked on another
/// regional relay still connects through it.
const CENTRAL_RELAY: &str = "turn:node.in.net:3478";

/// Regional relays: UDP/TCP, plus TLS on 443 for restrictive firewalls.
const EU_RELAYS: [&str; 2] = [
    "turn:eu.node.in.net:3478",
    "turns:eu.node.in.net:443?transport=tcp",
];
/// Not deployed yet. While this is empty, picking the US region yields the same
/// list as Auto (see the fallback below) rather than the central relay alone.
const US_RELAYS: [&str; 0] = [];

pub fn get_turn_credentials(
    login: &str,
    secret: &str,
    region: TurnRegion,
) -> Option<TurnCredentials> {
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
        // An explicit operator override describes the deployment we actually
        // run, so it is returned untouched — the region filter never applies.
        turn_servers_env
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    } else {
        let regional: Vec<String> = match region {
            TurnRegion::Auto => EU_RELAYS.iter().chain(US_RELAYS.iter()),
            TurnRegion::Eu => EU_RELAYS.iter().chain([].iter()),
            TurnRegion::Us => US_RELAYS.iter().chain([].iter()),
        }
        .map(|s| (*s).to_string())
        .collect();

        let mut uris = vec![CENTRAL_RELAY.to_string()];
        if regional.is_empty() {
            // The chosen region has no relays deployed; offering the central one
            // alone would be a downgrade, so fall back to everything we run.
            uris.extend(
                EU_RELAYS
                    .iter()
                    .chain(US_RELAYS.iter())
                    .map(|s| s.to_string()),
            );
        } else {
            uris.extend(regional);
        }
        uris
    };

    Some(TurnCredentials {
        username: turn_username,
        credential: turn_password,
        uris,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_turn_credentials_with_login() {
        let creds = get_turn_credentials("alice", "topsecret", TurnRegion::Auto).unwrap();
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
    fn eu_region_drops_us_relays_but_keeps_the_central_one() {
        let creds = get_turn_credentials("alice", "topsecret", TurnRegion::Eu).unwrap();
        assert!(
            creds.uris.iter().any(|u| u == CENTRAL_RELAY),
            "central relay must stay in every region: {:?}",
            creds.uris
        );
        assert!(
            creds.uris.iter().any(|u| u.contains("eu.node.in.net")),
            "eu region should offer the eu relays: {:?}",
            creds.uris
        );
        assert!(
            !creds.uris.iter().any(|u| u.contains("us.node.in.net")),
            "eu region must not offer the us relays: {:?}",
            creds.uris
        );
    }

    /// US relays are not deployed, so the region falls back to the full list
    /// instead of leaving the caller with the central relay alone.
    #[test]
    fn undeployed_region_falls_back_to_every_relay() {
        let creds = get_turn_credentials("alice", "topsecret", TurnRegion::Us).unwrap();
        let auto = get_turn_credentials("alice", "topsecret", TurnRegion::Auto).unwrap();
        assert!(creds.uris.iter().any(|u| u == CENTRAL_RELAY));
        assert_eq!(creds.uris, auto.uris);
    }

    #[test]
    fn auto_region_offers_every_relay() {
        let creds = get_turn_credentials("alice", "topsecret", TurnRegion::Auto).unwrap();
        assert_eq!(creds.uris.len(), 1 + EU_RELAYS.len() + US_RELAYS.len());
    }

    #[test]
    fn region_serializes_lowercase_and_defaults_to_auto() {
        assert_eq!(serde_json::to_string(&TurnRegion::Eu).unwrap(), r#""eu""#);
        assert_eq!(
            serde_json::from_str::<TurnRegion>(r#""us""#).unwrap(),
            TurnRegion::Us
        );
        assert_eq!(TurnRegion::default(), TurnRegion::Auto);
    }

    #[test]
    fn premium_username_format_is_timestamp_colon_login() {
        let creds = get_turn_credentials("bob", "secret", TurnRegion::Auto).unwrap();
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
