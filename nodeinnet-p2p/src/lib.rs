//! The node.in.net peer-to-peer core.  Everything two peers need to agree on and.

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

/// Base URL of the node.in.net service, as compiled in.  Prefer [`api_base()`] over.
#[cfg(debug_assertions)]
pub const API_BASE: &str = "http://127.0.0.1:8030";
#[cfg(not(debug_assertions))]
pub const API_BASE: &str = "https://node.in.net";

static ENDPOINT: std::sync::RwLock<Endpoint> = std::sync::RwLock::new(Endpoint {
    api: None,
    ws: None,
});

struct Endpoint {
    api: Option<String>,
    ws: Option<String>,
}

/// Point this process at a different node.in.net.  [`API_BASE`] is fixed at compile.
pub fn set_api_base(url: &str) {
    let mut ep = ENDPOINT.write().unwrap_or_else(|e| e.into_inner());
    ep.api = non_empty(url);
}

pub fn set_ws_base(url: &str) {
    let mut ep = ENDPOINT.write().unwrap_or_else(|e| e.into_inner());
    ep.ws = non_empty(url);
}

pub fn api_base() -> String {
    if let Some(url) = ENDPOINT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .api
        .clone()
    {
        return url;
    }
    std::env::var("NODEINNET_API")
        .ok()
        .and_then(|v| non_empty(&v))
        .unwrap_or_else(|| API_BASE.to_string())
}

pub fn ws_base(advertised: &str) -> String {
    if let Some(url) = ENDPOINT
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .ws
        .clone()
    {
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
    /// A copy safe to ANNOUNCE to peers/the server: every resource's `config` (which may.
    pub fn announced(&self) -> NodeInfo {
        NodeInfo {
            resources: self.resources.iter().map(|r| r.without_config()).collect(),
            ..self.clone()
        }
    }
}

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
