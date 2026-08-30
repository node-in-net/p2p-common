use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum RtcSignal {
    Offer {
        sdp: String,
        #[serde(default)]
        ice_restart: bool,
    },

    Answer {
        sdp: String,
    },

    IceCandidate {
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtcSignalEnvelope {
    pub to_node_id: String,
    pub signal: RtcSignal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundRtcSignal {
    pub from_node_id: String,
    pub signal: RtcSignal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnCredentials {
    pub username: String,
    pub credential: String,
    pub uris: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TurnRegion {
    #[default]
    Auto,
    Eu,
    Us,
    Main,
    Custom,
}

impl TurnRegion {
    pub fn as_str(&self) -> &'static str {
        match self {
            TurnRegion::Auto => "auto",
            TurnRegion::Eu => "eu",
            TurnRegion::Us => "us",
            TurnRegion::Main => "main",
            TurnRegion::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Option<TurnRegion> {
        match s {
            "auto" => Some(TurnRegion::Auto),
            "eu" => Some(TurnRegion::Eu),
            "us" => Some(TurnRegion::Us),
            "main" => Some(TurnRegion::Main),
            "custom" => Some(TurnRegion::Custom),
            _ => None,
        }
    }
}

const CENTRAL_RELAY: &str = "turn:node.in.net:3478";

const EU_RELAYS: [&str; 2] = [
    "turn:eu.node.in.net:3478",
    "turns:eu.node.in.net:443?transport=tcp",
];
const US_RELAYS: [&str; 0] = [];

pub fn get_turn_credentials(
    login: &str,
    secret: &str,
    region: TurnRegion,
) -> Option<TurnCredentials> {
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
        if matches!(region, TurnRegion::Main | TurnRegion::Custom) {
            return Some(TurnCredentials {
                username: turn_username,
                credential: turn_password,
                uris: vec![CENTRAL_RELAY.to_string()],
            });
        }

        let regional: Vec<String> = match region {
            TurnRegion::Eu => EU_RELAYS.to_vec(),
            TurnRegion::Us => US_RELAYS.to_vec(),
            _ => EU_RELAYS.iter().chain(US_RELAYS.iter()).copied().collect(),
        }
        .iter()
        .map(|s| (*s).to_string())
        .collect();

        let mut uris = vec![CENTRAL_RELAY.to_string()];
        if regional.is_empty() {
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
    fn main_region_stays_on_the_central_relay() {
        let creds = get_turn_credentials("alice", "topsecret", TurnRegion::Main).unwrap();
        assert_eq!(
            creds.uris,
            vec![CENTRAL_RELAY.to_string()],
            "Main must not be widened with regional hosts"
        );
    }

    #[test]
    fn region_round_trips_through_its_string_form() {
        for r in [
            TurnRegion::Auto,
            TurnRegion::Eu,
            TurnRegion::Us,
            TurnRegion::Main,
            TurnRegion::Custom,
        ] {
            assert_eq!(TurnRegion::parse(r.as_str()), Some(r));
        }
        assert_eq!(TurnRegion::parse("moon"), None);
    }

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
