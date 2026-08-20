//! The node.in.net peer-to-peer core.
//!
//! Everything two peers need to agree on and nothing else: the command set
//! ([`p2p::P2pMessage`]), the BSON wire format, the node/resource model, and the
//! WebRTC signalling types ([`rtc`]).
//!
//! This crate is deliberately free of application logic, transport code, I/O and
//! account concerns. It is pure data plus (de)serialisation, so every project
//! that speaks the protocol — the node.in.net service, Ice Commander — can share
//! one definition of it and cannot drift.

use serde::{Deserialize, Serialize};

pub mod account;
pub mod crypto;
pub mod p2p;
pub mod rtc;
pub mod ws;

pub use account::*;
pub use crypto::*;
pub use p2p::*;
pub use rtc::*;
pub use ws::*;

/// Base URL of the node.in.net service, as compiled in.
///
/// Prefer [`api_base()`] over reading this directly — it is only the last fallback, and a
/// consumer that reads the constant cannot be pointed anywhere else.
#[cfg(debug_assertions)]
pub const API_BASE: &str = "http://127.0.0.1:8030";
#[cfg(not(debug_assertions))]
pub const API_BASE: &str = "https://node.in.net";

/// Where the WebSocket lives, when the caller wants something other than what the server
/// advertised. Empty by default — see [`ws_base()`].
static ENDPOINT: std::sync::RwLock<Endpoint> = std::sync::RwLock::new(Endpoint {
    api: None,
    ws: None,
});

struct Endpoint {
    api: Option<String>,
    ws: Option<String>,
}

/// Point this process at a different node.in.net.
///
/// [`API_BASE`] is fixed at compile time — a debug build targets a local dev server, a
/// release build the live service — so a shipped binary can otherwise never be aimed
/// elsewhere. That blocks two real needs: a test suite that drives a RELEASE binary against
/// a local server, and a user who runs their own.
///
/// Call this before signing in; it affects every later [`api_base()`] read. Passing an
/// empty string clears the override and restores the compiled-in default.
pub fn set_api_base(url: &str) {
    let mut ep = ENDPOINT.write().unwrap_or_else(|e| e.into_inner());
    ep.api = non_empty(url);
}

/// Override the signalling socket the server advertises in its login response.
///
/// A dev server usually advertises the address it is reachable at from OUTSIDE, which is
/// not the one a client on the same machine can dial. Empty clears the override.
pub fn set_ws_base(url: &str) {
    let mut ep = ENDPOINT.write().unwrap_or_else(|e| e.into_inner());
    ep.ws = non_empty(url);
}

/// The base URL to reach the account API at.
///
/// Resolution order, most specific first:
///
/// 1. whatever [`set_api_base()`] was last given — a setting, a command-line flag, a test;
/// 2. the `NODEINNET_API` environment variable, which is how the apps and their test
///    harnesses have always pointed a build at a dev server;
/// 3. [`API_BASE`], compiled in per profile.
pub fn api_base() -> String {
    if let Some(url) = ENDPOINT.read().unwrap_or_else(|e| e.into_inner()).api.clone() {
        return url;
    }
    std::env::var("NODEINNET_API")
        .ok()
        .and_then(|v| non_empty(&v))
        .unwrap_or_else(|| API_BASE.to_string())
}

/// The signalling socket to dial, given what the server advertised.
///
/// Same order as [`api_base()`]: an explicit [`set_ws_base()`], then `NODEINNET_WS`, then
/// what the server said — which is what every ordinary run uses.
pub fn ws_base(advertised: &str) -> String {
    if let Some(url) = ENDPOINT.read().unwrap_or_else(|e| e.into_inner()).ws.clone() {
        return url;
    }
    std::env::var("NODEINNET_WS")
        .ok()
        .and_then(|v| non_empty(&v))
        .unwrap_or_else(|| advertised.to_string())
}

fn non_empty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// One peer on the network, as announced to the signalling server and to other
/// peers, together with the resources it shares.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeInfo {
    pub id: String,
    pub name: String,
    pub os: String,
    pub version: String,
    pub app_type: String,
    pub build_type: String,
    pub public_key: String,
    pub resources: Vec<SharedResource>,
    #[serde(default = "default_is_online")]
    pub is_online: bool,
    #[serde(default)]
    pub last_used: i64,
    #[serde(default)]
    pub is_temporary: bool,
}

impl NodeInfo {
    /// A copy safe to ANNOUNCE to peers/the server: every resource's `config`
    /// (which may hold a local path) is stripped. The serving node keeps its own
    /// local copy and resolves the base path by resource id, so local paths never
    /// travel the wire.
    pub fn announced(&self) -> NodeInfo {
        NodeInfo {
            resources: self.resources.iter().map(|r| r.without_config()).collect(),
            ..self.clone()
        }
    }
}

/// Locally remembered metadata about a peer we have seen before.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PeerConfig {
    pub name: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub last_known_addresses: Vec<String>,
}

/// A peer's shared resources plus the identifying fields shown next to them.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResourceWrapper {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub app_type: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    pub resources: Vec<SharedResource>,
}

fn default_is_online() -> bool {
    true
}

use std::collections::HashMap;
use std::sync::RwLock;

pub static KNOWN_PUBLIC_KEYS: std::sync::OnceLock<RwLock<HashMap<String, String>>> =
    std::sync::OnceLock::new();

pub static KNOWN_PEER_NAMES: std::sync::OnceLock<RwLock<HashMap<String, String>>> =
    std::sync::OnceLock::new();

pub static KNOWN_RESOURCE_NAMES: std::sync::OnceLock<RwLock<HashMap<(String, String), String>>> =
    std::sync::OnceLock::new();

pub fn get_known_public_key(node_id: &str) -> Option<String> {
    KNOWN_PUBLIC_KEYS.get()?.read().ok()?.get(node_id).cloned()
}

pub fn get_known_peer_name(node_id: &str) -> Option<String> {
    KNOWN_PEER_NAMES.get()?.read().ok()?.get(node_id).cloned()
}

pub fn get_known_resource_name(peer_id: &str, resource_id: &str) -> Option<String> {
    KNOWN_RESOURCE_NAMES
        .get()?
        .read()
        .ok()?
        .get(&(peer_id.to_string(), resource_id.to_string()))
        .cloned()
}

pub fn update_known_public_keys(nodes: &[NodeInfo]) {
    let map = KNOWN_PUBLIC_KEYS.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(mut write) = map.write() {
        for n in nodes {
            write.insert(n.id.clone(), n.public_key.clone());
        }
    }
    let names_map = KNOWN_PEER_NAMES.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(mut write) = names_map.write() {
        for n in nodes {
            write.insert(n.id.clone(), n.name.clone());
        }
    }
    let res_map = KNOWN_RESOURCE_NAMES.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(mut write) = res_map.write() {
        for n in nodes {
            for r in &n.resources {
                write.insert((n.id.clone(), r.id.clone()), r.name.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, name: &str, pub_key: &str, resources: Vec<SharedResource>) -> NodeInfo {
        NodeInfo {
            id: id.to_string(),
            name: name.to_string(),
            os: "linux".to_string(),
            version: "1.0".to_string(),
            app_type: "test".to_string(),
            build_type: "debug".to_string(),
            public_key: pub_key.to_string(),
            resources,
            is_online: true,
            last_used: 0,
            is_temporary: false,
        }
    }

    #[test]
    fn unknown_node_returns_none_before_update() {
        assert!(get_known_public_key("nonexistent_node_xyz").is_none());
        assert!(get_known_peer_name("nonexistent_node_xyz").is_none());
    }

    #[test]
    fn update_and_get_public_key() {
        let node = make_node("test_node_pk_001", "Node One", "pubkey_abc", vec![]);
        update_known_public_keys(&[node]);
        assert_eq!(
            get_known_public_key("test_node_pk_001"),
            Some("pubkey_abc".into())
        );
    }

    #[test]
    fn update_and_get_peer_name() {
        let node = make_node("test_node_name_001", "My Device", "key", vec![]);
        update_known_public_keys(&[node]);
        assert_eq!(
            get_known_peer_name("test_node_name_001"),
            Some("My Device".into())
        );
    }

    #[test]
    fn update_and_get_resource_name() {
        use p2p::ResourceType;
        let resource = SharedResource {
            id: "res_001".to_string(),
            name: "My Files".to_string(),
            resource_type: ResourceType::Filesystem,
            config: None,
            is_active: true,
            session_token: None,
        };
        let node = make_node("test_node_res_001", "Node", "key", vec![resource]);
        update_known_public_keys(&[node]);
        assert_eq!(
            get_known_resource_name("test_node_res_001", "res_001"),
            Some("My Files".into())
        );
    }

    #[test]
    fn update_multiple_nodes_all_accessible() {
        let node_a = make_node("multi_a", "Alpha", "key_a", vec![]);
        let node_b = make_node("multi_b", "Beta", "key_b", vec![]);
        update_known_public_keys(&[node_a, node_b]);
        assert_eq!(get_known_public_key("multi_a"), Some("key_a".into()));
        assert_eq!(get_known_public_key("multi_b"), Some("key_b".into()));
        assert_eq!(get_known_peer_name("multi_a"), Some("Alpha".into()));
        assert_eq!(get_known_peer_name("multi_b"), Some("Beta".into()));
    }

    #[test]
    fn update_overwrites_existing_key() {
        let node_v1 = make_node("test_node_overwrite", "Old Name", "old_key", vec![]);
        update_known_public_keys(&[node_v1]);
        assert_eq!(
            get_known_public_key("test_node_overwrite"),
            Some("old_key".into())
        );

        let node_v2 = make_node("test_node_overwrite", "New Name", "new_key", vec![]);
        update_known_public_keys(&[node_v2]);
        assert_eq!(
            get_known_public_key("test_node_overwrite"),
            Some("new_key".into())
        );
        assert_eq!(
            get_known_peer_name("test_node_overwrite"),
            Some("New Name".into())
        );
    }

    #[test]
    fn unknown_resource_returns_none() {
        assert!(get_known_resource_name("no_such_node", "no_such_res").is_none());
    }
}
