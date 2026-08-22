use serde::{Deserialize, Serialize};

pub mod account;
pub mod crypto;
pub mod rtc;
pub mod ws;

pub use account::*;
pub use crypto::*;
pub use rtc::*;
pub use ws::*;

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SharedResource {
    pub id: String,
    pub name: String,
    pub resource_type: ResourceType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl SharedResource {
    /// A copy safe to ANNOUNCE to peers/the server: `config` (which may hold a local.
    pub fn without_config(&self) -> SharedResource {
        SharedResource {
            config: None,
            ..self.clone()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Filesystem,
    SystemInfo,
    Terminal,
    Registry,
    SharedNetwork,

    SyncFolder,
    RemoteDesktop,
}

impl ResourceType {
    pub fn is_only_local(&self) -> bool {
        matches!(self, ResourceType::SyncFolder)
    }

    pub fn is_only_remote(&self) -> bool {
        matches!(
            self,
            ResourceType::Terminal | ResourceType::SharedNetwork | ResourceType::RemoteDesktop
        )
    }
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

