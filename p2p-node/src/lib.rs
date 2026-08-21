pub mod local_mesh;
pub mod mdns_discovery;

use nodeinnet_p2p::{NodeInfo, P2pMessage};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::{mpsc, Mutex};

#[async_trait::async_trait]
pub trait MessageHandler: Send + Sync {
    async fn handle(&self, msg: P2pMessage, ctx: NodeContext);
}

static MESSAGE_HANDLER: OnceLock<Arc<dyn MessageHandler>> = OnceLock::new();

pub fn install_message_handler(
    handler: Arc<dyn MessageHandler>,
) -> Result<(), Arc<dyn MessageHandler>> {
    MESSAGE_HANDLER.set(handler)
}

static APP_VERSION: OnceLock<String> = OnceLock::new();

pub fn set_app_version(version: impl Into<String>) {
    let _ = APP_VERSION.set(version.into());
}

pub fn app_version() -> &'static str {
    APP_VERSION.get().map(String::as_str).unwrap_or("0.0.0")
}

pub fn message_handler() -> Option<&'static Arc<dyn MessageHandler>> {
    MESSAGE_HANDLER.get()
}


#[derive(Clone, Debug)]
pub enum LocalP2pEvent {
    TransferProgress {
        transfer_id: uuid::Uuid,
        file_name: String,
        bytes_read: u64,
        total_bytes: u64,
    },
    TransferComplete {
        transfer_id: uuid::Uuid,
        file_name: String,
        is_upload: bool,
    },
    RemoteDesktopFrame {
        resource_id: String,
        bgra_data: Vec<u8>,
        width: usize,
        height: usize,
        compressed_size: usize,
    },
    RemoteDesktopStopped {
        resource_id: String,
    },
}

pub type ActiveDownload = (PathBuf, u64, Option<u32>);

pub type ActiveTerminal = (mpsc::Sender<Vec<u8>>, mpsc::Sender<(u16, u16)>, uuid::Uuid);

#[derive(Clone)]
pub struct NodeContext {
    pub outgoing_tx: mpsc::Sender<nodeinnet_p2p::OutboundP2pPayload>,

    pub log_tx: mpsc::Sender<String>,

    pub local_event_tx: mpsc::Sender<LocalP2pEvent>,

    pub my_info: NodeInfo,

    pub is_authenticated: Arc<AtomicBool>,

    pub remote_resources: Arc<Mutex<HashMap<nodeinnet_p2p::p2p::ResourceType, String>>>,

    pub active_uploads: Arc<Mutex<HashMap<uuid::Uuid, PathBuf>>>,
    pub active_downloads: Arc<Mutex<HashMap<uuid::Uuid, ActiveDownload>>>,

    pub active_terminals: Arc<Mutex<HashMap<String, ActiveTerminal>>>,
    pub active_socks_streams: Arc<Mutex<HashMap<uuid::Uuid, mpsc::Sender<Vec<u8>>>>>,
    pub active_ftp_uploads: Arc<Mutex<HashMap<uuid::Uuid, String>>>,

    /// Session-bound Cryptographic Tokens (Resource ID -> HMAC Token)
    pub session_keys: Arc<Mutex<HashMap<String, String>>>,

    pub rx_binary_buffers: Arc<Mutex<HashMap<String, Vec<u8>>>>,

    pub peer_max_chunk_size: Arc<std::sync::atomic::AtomicUsize>,
    pub discovered_ips: Arc<Mutex<Vec<String>>>,
    pub config: client_config::AppConfig,

    /// Serializes all framed writes to this connection's WebRTC DataChannel. Multiple tasks.
    pub dc_write_lock: Arc<Mutex<()>>,

    /// Serializes SDP (re)negotiations on this connection's PeerConnection. Remote Desktop.
    pub negotiation_lock: Arc<Mutex<()>>,
}

impl NodeContext {
    pub fn new(
        outgoing_tx: mpsc::Sender<nodeinnet_p2p::OutboundP2pPayload>,
        log_tx: mpsc::Sender<String>,
        local_event_tx: mpsc::Sender<LocalP2pEvent>,
        my_info: NodeInfo,
        config: client_config::AppConfig,
    ) -> Self {
        Self {
            outgoing_tx,
            log_tx,
            local_event_tx,
            my_info,
            is_authenticated: Arc::new(AtomicBool::new(false)),
            remote_resources: Arc::new(Mutex::new(HashMap::new())),
            active_uploads: Arc::new(Mutex::new(HashMap::new())),
            active_downloads: Arc::new(Mutex::new(HashMap::new())),

            active_terminals: Arc::new(Mutex::new(HashMap::new())),
            active_socks_streams: Arc::new(Mutex::new(HashMap::new())),
            active_ftp_uploads: Arc::new(Mutex::new(HashMap::new())),
            session_keys: Arc::new(Mutex::new(HashMap::new())),
            rx_binary_buffers: Arc::new(Mutex::new(HashMap::new())),
            peer_max_chunk_size: Arc::new(std::sync::atomic::AtomicUsize::new(10240)),
            discovered_ips: Arc::new(Mutex::new(Vec::new())),
            config,
            dc_write_lock: Arc::new(Mutex::new(())),
            negotiation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn log(&self, msg: impl Into<String>) {
        let text = msg.into();
        let tx = self.log_tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(text).await;
        });
    }

    pub async fn send_msg(&self, msg: P2pMessage) {
        let mac = if let Some(res_id) = msg.resource_id() {
            let session_keys = self.session_keys.lock().await;
            if let Some(key_hex) = session_keys.get(res_id) {
                if let Ok(bson_bytes) = nodeinnet_p2p::p2p::to_bson_vec(&msg) {
                    let computed = nodeinnet_p2p::crypto::compute_hmac_sha256(&bson_bytes, key_hex);
                    self.log(format!(
                        "✍️ [p2p-node] Signed message for resource {} (MAC: {}...)",
                        res_id,
                        &computed[..8]
                    ));
                    Some(computed)
                } else {
                    self.log(
                        "⚠️ [p2p-node] Failed to serialize BSON during signature generation!"
                            .to_string(),
                    );
                    None
                }
            } else {
                self.log(format!(
                    "⚠️ [p2p-node] Token not found for resource {}! MAC = None",
                    res_id
                ));
                None
            }
        } else {
            None
        };

        let envelope = nodeinnet_p2p::SecuredP2pEnvelope { mac, message: msg };

        let _ = self
            .outgoing_tx
            .send(nodeinnet_p2p::OutboundP2pPayload::Message(envelope))
            .await;
    }

    pub async fn send_binary(&self, data: Vec<u8>) {
        let _ = self
            .outgoing_tx
            .send(nodeinnet_p2p::OutboundP2pPayload::Binary(data))
            .await;
    }

    pub async fn shutdown(&self) {
        self.active_terminals.lock().await.clear();
        self.active_socks_streams.lock().await.clear();
        self.session_keys.lock().await.clear();
    }

    pub async fn process_message(&self, p2p_msg: P2pMessage) {
        let is_response = matches!(
            &p2p_msg,
            P2pMessage::EntriesResponse { .. }
                | P2pMessage::MetadataResponse { .. }
                | P2pMessage::CreateDirectoryResponse { .. }
                | P2pMessage::DeleteEntryResponse { .. }
                | P2pMessage::RenameEntryResponse { .. }
                | P2pMessage::SetPermissionsResponse { .. }
                | P2pMessage::SystemInfoResponse { .. }
                | P2pMessage::RegistryKeysResponse { .. }
                | P2pMessage::CreateRegistryKeyResponse { .. }
                | P2pMessage::DeleteRegistryEntryResponse { .. }
                | P2pMessage::SetRegistryValueResponse { .. }
                | P2pMessage::HttpResponseStart { .. }
                | P2pMessage::HttpResponseChunk { .. }
                | P2pMessage::HttpResponseComplete { .. }
                | P2pMessage::SocksConnectResponse { .. }
                | P2pMessage::SocksData { .. }
                | P2pMessage::SocksClose { .. }
                | P2pMessage::FileTransferResponse { .. }
                | P2pMessage::FileChunk { .. }
                | P2pMessage::FileTransferComplete { .. }
                | P2pMessage::TerminalOutput { .. }
                | P2pMessage::SyncStateResponse { .. }
                | P2pMessage::RemoteDesktopResponse { .. }
                | P2pMessage::HandshakeResponse { .. }
        );

        if !is_response {
            if let Some(res_id) = p2p_msg.resource_id() {
                if let Some(resource) = self.my_info.resources.iter().find(|r| r.id == *res_id) {
                    let allowed_types = p2p_msg.allowed_resource_types();
                    if !allowed_types.is_empty() && !allowed_types.contains(&resource.resource_type)
                    {
                        self.log(format!("❌ RBAC Security Violation: Message {:?} is strictly forbidden for resource type {:?}", p2p_msg, resource.resource_type));
                        return; // Drop message unconditionally
                    }
                } else {
                    self.log(format!("❌ RBAC Security Violation: Peer attempted to access non-existent or unshared resource '{}'", res_id));
                    return; // Drop message unconditionally
                }
            }
        }

        match p2p_msg {
            P2pMessage::Handshake {
                requested_resources,
                ..
            } => {
                let mut my_resources = self.my_info.resources.clone();
                let mut session_keys = self.session_keys.lock().await;

                if let Some(req_types) = requested_resources {
                    my_resources.retain(|r| req_types.contains(&r.resource_type));
                }

                for res in my_resources.iter_mut() {
                    let token = nodeinnet_p2p::crypto::generate_session_token();
                    self.log(format!(
                        "🔑 [P2P-NODE KEYGEN] Created local session token for resource: {} ({})",
                        res.id,
                        &token[..4]
                    ));
                    res.session_token = Some(token.clone());
                    // LOCAL-ONLY: never ship the resource's config (local path) to the peer — we resolve.
                    res.config = None;
                    session_keys.insert(res.id.clone(), token);
                }

                self.send_msg(P2pMessage::HandshakeResponse {
                    resources: my_resources,
                })
                .await;
            }

            P2pMessage::RemoteDesktopRequest {
                resource_id, start, ..
            } => {
                let success = self.my_info.resources.iter().any(|r| {
                    r.id == resource_id
                        && r.is_active
                        && r.resource_type == nodeinnet_p2p::ResourceType::RemoteDesktop
                });
                if success {
                    self.log(format!(
                        "🟢 Approved Remote Desktop start command for resource {} (start={})",
                        resource_id, start
                    ));
                    self.send_msg(P2pMessage::RemoteDesktopResponse {
                        resource_id,
                        success: true,
                        error_msg: None,
                        width: None,
                        height: None,
                    })
                    .await;
                } else {
                    self.log(format!("❌ Denied Remote Desktop start command for resource {}: not found or inactive", resource_id));
                    self.send_msg(P2pMessage::RemoteDesktopResponse {
                        resource_id,
                        success: false,
                        error_msg: Some(
                            "Remote desktop service is inactive or unavailable".to_string(),
                        ),
                        width: None,
                        height: None,
                    })
                    .await;
                }
            }

            other => {
                if let Some(handler) = message_handler() {
                    handler.handle(other, self.clone()).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_node_info() -> nodeinnet_p2p::NodeInfo {
        nodeinnet_p2p::NodeInfo {
            id: "test_node_ctx".to_string(),
            name: "Test Node".to_string(),
            os: "linux".to_string(),
            version: "1.0".to_string(),
            app_type: "test".to_string(),
            build_type: "debug".to_string(),
            public_key: "key".to_string(),
            resources: vec![],
            is_online: true,
            last_used: 0,
            is_temporary: false,
        }
    }

    fn make_test_context() -> NodeContext {
        let (outgoing_tx, _) = mpsc::channel(1);
        let (log_tx, _) = mpsc::channel(1);
        let (event_tx, _) = mpsc::channel(1);
        let config = client_config::AppConfig::new("p2p-node-unit-test");
        NodeContext::new(outgoing_tx, log_tx, event_tx, make_test_node_info(), config)
    }

    #[test]
    fn node_context_starts_unauthenticated() {
        let ctx = make_test_context();
        assert!(!ctx
            .is_authenticated
            .load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn node_context_default_chunk_size_is_10240() {
        let ctx = make_test_context();
        assert_eq!(
            ctx.peer_max_chunk_size
                .load(std::sync::atomic::Ordering::Relaxed),
            10240
        );
    }

    #[tokio::test]
    async fn shutdown_clears_session_keys() {
        let ctx = make_test_context();
        ctx.session_keys
            .lock()
            .await
            .insert("res1".to_string(), "token1".to_string());
        assert!(!ctx.session_keys.lock().await.is_empty());

        ctx.shutdown().await;
        assert!(ctx.session_keys.lock().await.is_empty());
    }
}
