use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Message protocol between peers (nodes) over the P2P channel (WebRTC Data Channel).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "cmd", content = "data")]
pub enum P2pMessage {
    // --- Basic commands ---
    Ping(u64),
    Pong(u64),
    Goodbye,
    TextMessage {
        text: String,
    },

    Handshake {
        node_version: String,
        timestamp_ms: u64,
        signature: String, // Ed25519 signature of: my_id + ":" + peer_id + ":" + timestamp_ms
        #[serde(default)]
        requested_resources: Option<Vec<ResourceType>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chunk_size: Option<usize>, // Largest chunk (bytes/chars) this peer can accept
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local_tcp_port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_node_id: Option<String>,
    },

    HandshakeResponse {
        resources: Vec<SharedResource>,
    },

    PeersSync {
        nodes: Vec<crate::NodeInfo>,
        addresses: std::collections::HashMap<String, Vec<String>>,
    },

    // --- Filesystem navigation ---
    RequestEntries {
        request_id: Uuid,
        resource_id: String, // Resource ID (e.g. a drive)
        path: String,        // Path inside the resource
    },
    EntriesResponse {
        request_id: Uuid,
        resource_id: String,
        path: String,
        directories: Vec<String>,
        files: Vec<(String, u64)>, // Name, Size
        #[serde(default)]
        directories_with_dates: Option<Vec<(String, String)>>, // Name, Date
        #[serde(default)]
        files_with_dates: Option<Vec<(String, u64, String)>>, // Name, Size, Date
        #[serde(default)]
        directories_permissions: Option<Vec<Option<u32>>>,
        #[serde(default)]
        files_permissions: Option<Vec<Option<u32>>>,
    },
    RequestMetadata {
        request_id: Uuid,
        resource_id: String,
        path: String,
    },
    MetadataResponse {
        request_id: Uuid,
        resource_id: String,
        path: String,
        metadata: Option<EntryInfo>, // None when the file/dir was not found
    },

    // --- File and directory management ---
    CreateDirectoryRequest {
        request_id: Uuid,
        resource_id: String,
        parent_path: String,
        dir_name: String,
        permissions: Option<u32>,
    },
    CreateDirectoryResponse {
        request_id: Uuid,
        resource_id: String,
        parent_path: String, // Path that should be refreshed
        result: Result<(), String>,
    },
    DeleteEntryRequest {
        request_id: Uuid,
        resource_id: String,
        path: String, // Full path of the file/directory
    },
    DeleteEntryResponse {
        request_id: Uuid,
        resource_id: String,
        parent_path: String, // Path that should be refreshed
        result: Result<(), String>,
    },
    RenameEntryRequest {
        request_id: Uuid,
        resource_id: String,
        path: String,     // Current full path
        new_path: String, // New full path
    },
    RenameEntryResponse {
        request_id: Uuid,
        resource_id: String,
        parent_path: String, // Path the UI should refresh
        result: Result<(), String>,
    },
    SetPermissionsRequest {
        request_id: Uuid,
        resource_id: String,
        path: String,
        permissions: u32,
    },
    SetPermissionsResponse {
        request_id: Uuid,
        resource_id: String,
        parent_path: String,
        result: Result<(), String>,
    },

    // --- System information ---
    RequestSystemInfo {
        resource_id: String,
    },

    SystemInfoResponse {
        resource_id: String,
        info: SysInfo,
    },

    // --- Remote terminal ---
    StartTerminal {
        resource_id: String,
    },
    StopTerminal {
        resource_id: String,
    },
    TerminalInput {
        resource_id: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    TerminalOutput {
        resource_id: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    TerminalResize {
        resource_id: String,
        rows: u16,
        cols: u16,
    },

    // --- File transfer ---
    FileDownloadRequest {
        resource_id: String,
        file_path: String,
        /// Unique ID of this particular transfer session
        transfer_id: Uuid,
    },
    FileUploadRequest {
        resource_id: String,
        target_path: String, // Where to save the file
        file_name: String,
        total_size: u64,
        /// Unique ID of this particular transfer session
        transfer_id: Uuid,
        permissions: Option<u32>,
    },
    FileTransferResponse {
        transfer_id: Uuid,
        status: FileTransferStatus,
    },
    FileChunk {
        transfer_id: Uuid,
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    FileTransferComplete {
        transfer_id: Uuid,
        checksum: Option<String>, // e.g., "sha256:...."
    },

    // --- Windows registry ---
    RequestRegistryKeys {
        request_id: Uuid,
        resource_id: String,
        path: String,
    },
    RegistryKeysResponse {
        request_id: Uuid,
        resource_id: String,
        path: String,
        subkeys: Vec<String>,
        values: Vec<RegistryValueInfo>,
        error: Option<String>, // Error when access is denied
    },
    CreateRegistryKeyRequest {
        request_id: Uuid,
        resource_id: String,
        parent_path: String,
        key_name: String,
    },
    CreateRegistryKeyResponse {
        request_id: Uuid,
        resource_id: String,
        parent_path: String,
        result: Result<(), String>,
    },
    DeleteRegistryEntryRequest {
        request_id: Uuid,
        resource_id: String,
        path: String,
        value_name: Option<String>,
        is_key: bool,
    },
    DeleteRegistryEntryResponse {
        request_id: Uuid,
        resource_id: String,
        parent_path: String,
        result: Result<(), String>,
    },
    SetRegistryValueRequest {
        request_id: Uuid,
        resource_id: String,
        path: String, // Registry key path
        value_name: String,
        value_data: RegistryValueData,
    },
    SetRegistryValueResponse {
        request_id: Uuid,
        resource_id: String,
        path: String, // Registry key path
        result: Result<(), String>,
    },

    // --- Shared Network (SOCKS5 Tunneling) ---
    SocksConnectRequest {
        resource_id: String,
        stream_id: Uuid,
        host: String,
        port: u16,
    },
    SocksConnectResponse {
        resource_id: String,
        stream_id: Uuid,
        is_success: bool,
        error_msg: Option<String>,
    },
    SocksData {
        resource_id: String,
        stream_id: Uuid,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>, // Raw traffic bytes
    },
    SocksClose {
        resource_id: String,
        stream_id: Uuid,
    },

    // --- Web VPN (HTTP Proxy) ---
    HttpRequest {
        resource_id: String,
        request_id: Uuid,
        method: String,
        url: String,
        headers: std::collections::BTreeMap<String, String>,
        body: Option<Vec<u8>>, // HttpRequest body can be left alone or mapped. If it's an array, it's fine.
    },
    HttpResponseStart {
        resource_id: String,
        request_id: Uuid,
        status: u16,
        headers: std::collections::BTreeMap<String, String>,
    },
    HttpResponseChunk {
        resource_id: String,
        request_id: Uuid,
        #[serde(with = "serde_bytes")]
        chunk: Vec<u8>,
    },
    HttpResponseComplete {
        resource_id: String,
        request_id: Uuid,
    },

    // --- Sync Folder ---
    SyncStateRequest {
        resource_id: String,
        target_folder_names: Vec<String>,
    },
    SyncStateResponse {
        resource_id: String,
        available_folders: std::collections::BTreeSet<String>,
        folder_states: std::collections::BTreeMap<String, Vec<SyncFileInfo>>,
    },

    // --- Remote Desktop ---
    RemoteDesktopRequest {
        resource_id: String,
        start: bool,
        #[serde(default)]
        original_size: bool,
        #[serde(default)]
        bitrate_bps: Option<u32>,
        #[serde(default)]
        force_select: bool,
    },
    RemoteDesktopResponse {
        resource_id: String,
        success: bool,
        error_msg: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        width: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        height: Option<usize>,
    },
    RemoteDesktopSdpOffer {
        resource_id: String,
        sdp: String,
    },
    RemoteDesktopSdpAnswer {
        resource_id: String,
        sdp: String,
    },
    RemoteDesktopInput {
        resource_id: String,
        event: DesktopInputEvent,
    },

    // --- Offline LAN Mesh Variants ---
    RtcSignal {
        target_node_id: String,
        signal_type: String, // "offer", "answer", or "candidate"
        sdp_or_candidate: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp_mid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sdp_mline_index: Option<u16>,
    },
    RequestTopology,
    ResponseTopology {
        peers: Vec<NodeTopologyInfo>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeTopologyInfo {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub last_known_addresses: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DesktopInputEvent {
    MouseMove { x: i32, y: i32 },
    MouseDown { button: u8 },
    MouseUp { button: u8 },
    MouseScroll { dy: i32 },
    KeyPress { keyval: u32 },
    KeyRelease { keyval: u32 },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SyncFileInfo {
    pub relative_path: String,
    pub md5_hash: String,
    pub size: u64,
    pub last_modified_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum SyncAction {
    Pull,
    Push,
    DeleteLocal,
    DeleteRemote,
    Ignore,
    NoneSelect,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileDifference {
    Modified,
    LocalOnly,
    RemoteOnly,
    Identical,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyncDiffItem {
    pub folder_name: String,
    pub relative_path: String,
    pub local_state: Option<SyncFileInfo>,
    pub remote_state: Option<SyncFileInfo>,
    pub difference: FileDifference,
}

impl P2pMessage {
    pub fn allowed_resource_types(&self) -> Vec<ResourceType> {
        match self {
            P2pMessage::RequestEntries { .. }
            | P2pMessage::EntriesResponse { .. }
            | P2pMessage::RequestMetadata { .. }
            | P2pMessage::MetadataResponse { .. }
            | P2pMessage::CreateDirectoryRequest { .. }
            | P2pMessage::CreateDirectoryResponse { .. }
            | P2pMessage::DeleteEntryRequest { .. }
            | P2pMessage::DeleteEntryResponse { .. }
            | P2pMessage::RenameEntryRequest { .. }
            | P2pMessage::RenameEntryResponse { .. }
            | P2pMessage::SetPermissionsRequest { .. }
            | P2pMessage::SetPermissionsResponse { .. }
            | P2pMessage::FileDownloadRequest { .. }
            | P2pMessage::FileUploadRequest { .. } => {
                vec![ResourceType::Filesystem, ResourceType::SyncFolder]
            }

            P2pMessage::RequestSystemInfo { .. } | P2pMessage::SystemInfoResponse { .. } => {
                vec![ResourceType::SystemInfo]
            }

            P2pMessage::StartTerminal { .. }
            | P2pMessage::StopTerminal { .. }
            | P2pMessage::TerminalInput { .. }
            | P2pMessage::TerminalOutput { .. }
            | P2pMessage::TerminalResize { .. } => vec![ResourceType::Terminal],

            P2pMessage::RequestRegistryKeys { .. }
            | P2pMessage::RegistryKeysResponse { .. }
            | P2pMessage::CreateRegistryKeyRequest { .. }
            | P2pMessage::CreateRegistryKeyResponse { .. }
            | P2pMessage::DeleteRegistryEntryRequest { .. }
            | P2pMessage::DeleteRegistryEntryResponse { .. }
            | P2pMessage::SetRegistryValueRequest { .. }
            | P2pMessage::SetRegistryValueResponse { .. } => vec![ResourceType::Registry],

            P2pMessage::SocksConnectRequest { .. }
            | P2pMessage::SocksConnectResponse { .. }
            | P2pMessage::SocksData { .. }
            | P2pMessage::SocksClose { .. }
            | P2pMessage::HttpRequest { .. }
            | P2pMessage::HttpResponseStart { .. }
            | P2pMessage::HttpResponseChunk { .. }
            | P2pMessage::HttpResponseComplete { .. } => vec![ResourceType::SharedNetwork],

            P2pMessage::SyncStateRequest { .. } | P2pMessage::SyncStateResponse { .. } => {
                vec![ResourceType::SyncFolder]
            }
            P2pMessage::RemoteDesktopRequest { .. }
            | P2pMessage::RemoteDesktopResponse { .. }
            | P2pMessage::RemoteDesktopSdpOffer { .. }
            | P2pMessage::RemoteDesktopSdpAnswer { .. }
            | P2pMessage::RemoteDesktopInput { .. } => vec![ResourceType::RemoteDesktop],

            // These do not target a resource ID directly
            P2pMessage::Ping(_)
            | P2pMessage::Pong(_)
            | P2pMessage::Goodbye
            | P2pMessage::TextMessage { .. }
            | P2pMessage::Handshake { .. }
            | P2pMessage::HandshakeResponse { .. }
            | P2pMessage::PeersSync { .. }
            | P2pMessage::FileTransferResponse { .. }
            | P2pMessage::FileChunk { .. }
            | P2pMessage::RtcSignal { .. }
            | P2pMessage::RequestTopology
            | P2pMessage::ResponseTopology { .. }
            | P2pMessage::FileTransferComplete { .. } => vec![],
        }
    }

    pub fn resource_id(&self) -> Option<&String> {
        match self {
            P2pMessage::RequestEntries { resource_id, .. } => Some(resource_id),
            P2pMessage::EntriesResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::RequestMetadata { resource_id, .. } => Some(resource_id),
            P2pMessage::MetadataResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::CreateDirectoryRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::CreateDirectoryResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::DeleteEntryRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::DeleteEntryResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::RenameEntryRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::RenameEntryResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::SetPermissionsRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::SetPermissionsResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::SystemInfoResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::StartTerminal { resource_id } => Some(resource_id),
            P2pMessage::StopTerminal { resource_id } => Some(resource_id),
            P2pMessage::TerminalInput { resource_id, .. } => Some(resource_id),
            P2pMessage::TerminalOutput { resource_id, .. } => Some(resource_id),
            P2pMessage::TerminalResize { resource_id, .. } => Some(resource_id),
            P2pMessage::HttpRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::HttpResponseStart { resource_id, .. } => Some(resource_id),
            P2pMessage::HttpResponseChunk { resource_id, .. } => Some(resource_id),
            P2pMessage::HttpResponseComplete { resource_id, .. } => Some(resource_id),
            P2pMessage::SocksConnectRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::SocksConnectResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::SocksData { resource_id, .. } => Some(resource_id),
            P2pMessage::SocksClose { resource_id, .. } => Some(resource_id),
            P2pMessage::RequestSystemInfo { resource_id } => Some(resource_id),
            P2pMessage::FileDownloadRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::FileUploadRequest { resource_id, .. } => Some(resource_id),

            P2pMessage::RegistryKeysResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::RequestRegistryKeys { resource_id, .. } => Some(resource_id),
            P2pMessage::CreateRegistryKeyRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::CreateRegistryKeyResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::DeleteRegistryEntryRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::DeleteRegistryEntryResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::SetRegistryValueRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::SetRegistryValueResponse { resource_id, .. } => Some(resource_id),

            P2pMessage::SyncStateRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::SyncStateResponse { resource_id, .. } => Some(resource_id),

            P2pMessage::RemoteDesktopRequest { resource_id, .. } => Some(resource_id),
            P2pMessage::RemoteDesktopResponse { resource_id, .. } => Some(resource_id),
            P2pMessage::RemoteDesktopSdpOffer { resource_id, .. } => Some(resource_id),
            P2pMessage::RemoteDesktopSdpAnswer { resource_id, .. } => Some(resource_id),
            P2pMessage::RemoteDesktopInput { resource_id, .. } => Some(resource_id),

            // These messages might not have resource_id or handle it differently
            P2pMessage::FileTransferResponse { .. } => None,
            P2pMessage::FileChunk { .. } => None,
            P2pMessage::FileTransferComplete { .. } => None,
            P2pMessage::TextMessage { .. } => None,
            P2pMessage::Handshake { .. } => None,
            P2pMessage::Goodbye => None,
            P2pMessage::Ping(_) => None,
            P2pMessage::Pong(_) => None,
            P2pMessage::HandshakeResponse { .. } => None,
            P2pMessage::PeersSync { .. } => None,
            P2pMessage::RtcSignal { .. } => None,
            P2pMessage::RequestTopology => None,
            P2pMessage::ResponseTopology { .. } => None,
        }
    }

    pub fn set_resource_id(&mut self, new_id: String) {
        match self {
            P2pMessage::RequestEntries { resource_id, .. } => *resource_id = new_id,
            P2pMessage::EntriesResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RequestMetadata { resource_id, .. } => *resource_id = new_id,
            P2pMessage::MetadataResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::CreateDirectoryRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::CreateDirectoryResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::DeleteEntryRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::DeleteEntryResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RenameEntryRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RenameEntryResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SetPermissionsRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SetPermissionsResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RequestSystemInfo { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SystemInfoResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::StartTerminal { resource_id, .. } => *resource_id = new_id,
            P2pMessage::StopTerminal { resource_id, .. } => *resource_id = new_id,
            P2pMessage::TerminalInput { resource_id, .. } => *resource_id = new_id,
            P2pMessage::TerminalOutput { resource_id, .. } => *resource_id = new_id,
            P2pMessage::TerminalResize { resource_id, .. } => *resource_id = new_id,
            P2pMessage::FileDownloadRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::FileUploadRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RequestRegistryKeys { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RegistryKeysResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::CreateRegistryKeyRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::CreateRegistryKeyResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::DeleteRegistryEntryRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::DeleteRegistryEntryResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SetRegistryValueRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SetRegistryValueResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SocksConnectRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SocksConnectResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SocksData { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SocksClose { resource_id, .. } => *resource_id = new_id,
            P2pMessage::HttpRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::HttpResponseStart { resource_id, .. } => *resource_id = new_id,
            P2pMessage::HttpResponseChunk { resource_id, .. } => *resource_id = new_id,
            P2pMessage::HttpResponseComplete { resource_id, .. } => *resource_id = new_id,

            P2pMessage::SyncStateRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::SyncStateResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RemoteDesktopRequest { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RemoteDesktopResponse { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RemoteDesktopSdpOffer { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RemoteDesktopSdpAnswer { resource_id, .. } => *resource_id = new_id,
            P2pMessage::RemoteDesktopInput { resource_id, .. } => *resource_id = new_id,
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntryInfo {
    pub name: String,
    pub entry_type: String, // "File" or "Directory"
    pub size: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FileTransferStatus {
    Accepted { total_size: u64 },
    Rejected { reason: String },
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SharedResource {
    pub id: String,
    pub name: String,
    pub resource_type: ResourceType,
    /// Per-resource config (e.g. a local filesystem path). Stripped by
    /// [`SharedResource::without_config`] before it leaves the machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
    /// TEMPORARY SECRET. Issued only to an authorized peer within a P2P session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl SharedResource {
    /// A copy safe to ANNOUNCE to peers/the server: `config` (which may hold a
    /// local filesystem path) is dropped. The serving node keeps its own local
    /// copy and resolves the base path by resource id, so peers never learn it.
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SysInfo {
    pub hostname: String,
    #[serde(default)]
    pub os_family: String,
    pub os_type: String,
    pub os_version: String,
    pub cpu_arch: String,
    pub cpu_cores: usize,
    #[serde(default)]
    pub cpu_usage: f32, // percent (0.0 - 100.0)
    pub total_memory: u64, // bytes
    pub used_memory: u64,  // bytes
    pub total_swap: u64,   // bytes
    pub used_swap: u64,    // bytes
    pub uptime: u64,       // seconds
    #[serde(default)]
    pub network_interfaces: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistryValueInfo {
    pub name: String,
    pub data: RegistryValueData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RegistryValueData {
    String(String),
    MultiString(Vec<String>),
    DWord(u32),
    QWord(u64),
    #[serde(with = "serde_bytes")]
    Binary(Vec<u8>),
    ExpandString(String),
    Unknown,
}

/// Helper to serialize any Serde type directly to BSON bytes
pub fn to_bson_vec<T: serde::Serialize>(val: &T) -> Result<Vec<u8>, String> {
    bson::serialize_to_vec(val).map_err(|e| e.to_string())
}

/// Helper to deserialize any Serde type directly from BSON bytes
pub fn from_bson_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    bson::deserialize_from_slice(bytes).map_err(|e| e.to_string())
}

impl RegistryValueData {
    pub fn as_string(&self) -> String {
        match self {
            Self::String(s) => s.clone(),
            Self::MultiString(v) => v.join("\n"),
            Self::DWord(d) => format!("0x{:08X} ({})", d, d),
            Self::QWord(q) => format!("0x{:016X} ({})", q, q),
            Self::Binary(b) => format!("{:02X?}", b),
            Self::ExpandString(s) => s.clone(),
            Self::Unknown => "(Unknown Type)".to_string(),
        }
    }
}

/// Cryptographic envelope protecting P2P packets from cross-resource routing
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecuredP2pEnvelope {
    pub mac: Option<String>, // HMAC-SHA256 signature of the message JSON. None for resource-less commands (e.g. Handshake).
    pub message: P2pMessage,
}

/// Native wrapper carrying data from the p2p node into the client network core (WebRTC).
/// Separates textual JSON messages from streamed raw binary chunks.
#[derive(Debug, Clone)]
pub enum OutboundP2pPayload {
    Message(SecuredP2pEnvelope),
    UnsignedMessage(P2pMessage),
    Binary(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RecentResource {
    pub peer_id: String,
    pub peer_name: String,
    pub resource_id: String,
    pub resource_name: String,
    pub resource_type: ResourceType,
    pub last_accessed: u64,
    pub access_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ResourceType predicates ───────────────────────────────────────────────

    #[test]
    fn sync_folder_is_only_local() {
        assert!(ResourceType::SyncFolder.is_only_local());
    }

    #[test]
    fn filesystem_is_not_only_local() {
        assert!(!ResourceType::Filesystem.is_only_local());
    }

    #[test]
    fn terminal_is_only_remote() {
        assert!(ResourceType::Terminal.is_only_remote());
    }

    #[test]
    fn shared_network_is_only_remote() {
        assert!(ResourceType::SharedNetwork.is_only_remote());
    }

    #[test]
    fn remote_desktop_is_only_remote() {
        assert!(ResourceType::RemoteDesktop.is_only_remote());
    }

    // ── RegistryValueData::as_string ─────────────────────────────────────────

    #[test]
    fn registry_string_variant_returns_value() {
        let v = RegistryValueData::String("hello".to_string());
        assert_eq!(v.as_string(), "hello");
    }

    #[test]
    fn registry_expand_string_returns_value() {
        let v = RegistryValueData::ExpandString("%APPDATA%".to_string());
        assert_eq!(v.as_string(), "%APPDATA%");
    }

    #[test]
    fn registry_multi_string_joins_with_newline() {
        let v = RegistryValueData::MultiString(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(v.as_string(), "a\nb");
    }

    #[test]
    fn registry_dword_formats_hex_and_decimal() {
        let v = RegistryValueData::DWord(255);
        assert_eq!(v.as_string(), "0x000000FF (255)");
    }

    #[test]
    fn registry_qword_formats_hex_and_decimal() {
        let v = RegistryValueData::QWord(1);
        assert_eq!(v.as_string(), "0x0000000000000001 (1)");
    }

    #[test]
    fn registry_unknown_returns_label() {
        assert_eq!(RegistryValueData::Unknown.as_string(), "(Unknown Type)");
    }

    #[test]
    fn registry_binary_formats_as_hex_array() {
        let v = RegistryValueData::Binary(vec![0xDE, 0xAD]);
        let s = v.as_string();
        assert!(s.contains("DE"), "expected DE in {}", s);
        assert!(s.contains("AD"), "expected AD in {}", s);
    }

    // ── SharedResource default field ──────────────────────────────────────────

    #[test]
    fn shared_resource_is_active_defaults_to_true() {
        let json = r#"{"id":"r1","name":"Root","resource_type":"Filesystem"}"#;
        let res: SharedResource = serde_json::from_str(json).unwrap();
        assert!(res.is_active);
    }

    #[test]
    fn shared_resource_session_token_skipped_when_none() {
        let res = SharedResource {
            id: "r1".to_string(),
            name: "Root".to_string(),
            resource_type: ResourceType::Filesystem,
            config: None,
            is_active: true,
            session_token: None,
        };
        let json = serde_json::to_string(&res).unwrap();
        assert!(!json.contains("session_token"), "json: {}", json);
    }

    // ── P2pMessage serde tag ──────────────────────────────────────────────────

    #[test]
    fn ping_serializes_with_cmd_tag() {
        let msg = P2pMessage::Ping(42);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""cmd":"Ping""#), "json: {}", json);
        assert!(json.contains("42"), "json: {}", json);
    }

    #[test]
    fn ping_roundtrips_through_json() {
        let original = P2pMessage::Ping(999);
        let json = serde_json::to_string(&original).unwrap();
        let parsed: P2pMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, P2pMessage::Ping(999)));
    }

    #[test]
    fn goodbye_roundtrips_through_json() {
        let json = serde_json::to_string(&P2pMessage::Goodbye).unwrap();
        let parsed: P2pMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, P2pMessage::Goodbye));
    }

    // ── BSON roundtrip ────────────────────────────────────────────────────────

    #[test]
    fn bson_roundtrip_preserves_sys_info() {
        let original = SysInfo {
            hostname: "testhost".to_string(),
            os_family: "linux".to_string(),
            os_type: "Ubuntu".to_string(),
            os_version: "22.04".to_string(),
            cpu_arch: "x86_64".to_string(),
            cpu_cores: 4,
            cpu_usage: 12.5,
            total_memory: 8_000_000_000,
            used_memory: 2_000_000_000,
            total_swap: 1_000_000_000,
            used_swap: 0,
            uptime: 3600,
            network_interfaces: Vec::new(),
        };
        let bytes = to_bson_vec(&original).expect("serialize");
        let restored: SysInfo = from_bson_slice(&bytes).expect("deserialize");
        assert_eq!(restored.hostname, "testhost");
        assert_eq!(restored.cpu_cores, 4);
        assert_eq!(restored.total_memory, 8_000_000_000);
    }
}
