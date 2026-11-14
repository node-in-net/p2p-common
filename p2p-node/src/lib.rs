pub mod lan;

use nodeinnet_p2p::{NodeInfo, P2pMessage};
use std::collections::{HashMap, HashSet};
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

#[derive(Clone)]
pub struct ActiveDownload {
    pub path: PathBuf,
    pub total_size: u64,
    pub upload: Option<ActiveUpload>,
}

#[derive(Clone)]
pub struct ActiveUpload {
    pub file: Arc<Mutex<tokio::fs::File>>,
    pub temp: PathBuf,
    pub permissions: Option<u32>,
    pub stored: u64,
    pub reservation: Arc<dyn std::any::Any + Send + Sync>,
}

pub type ActiveTerminal = (mpsc::Sender<Vec<u8>>, mpsc::Sender<(u16, u16)>, uuid::Uuid);

#[derive(Clone)]
pub struct NodeContext {
    pub outgoing_tx: mpsc::Sender<nodeinnet_p2p::OutboundP2pPayload>,

    pub log_tx: mpsc::Sender<String>,

    pub local_event_tx: mpsc::Sender<LocalP2pEvent>,

    pub my_info: NodeInfo,

    pub peer_id: String,
    pub link: lan::Link,

    pub is_authenticated: Arc<AtomicBool>,
    pub session_up: Arc<AtomicBool>,

    pub remote_resources: Arc<Mutex<HashMap<nodeinnet_p2p::p2p::ResourceType, String>>>,
    pub peer_resources: Arc<Mutex<Option<Vec<nodeinnet_p2p::SharedResource>>>>,

    pub active_downloads: Arc<Mutex<HashMap<uuid::Uuid, ActiveDownload>>>,
    pub requested_downloads: Arc<Mutex<HashSet<uuid::Uuid>>>,
    pub unconfirmed_uploads: Arc<Mutex<HashSet<uuid::Uuid>>>,

    pub active_terminals: Arc<Mutex<HashMap<String, ActiveTerminal>>>,
    pub active_socks_streams: Arc<Mutex<HashMap<uuid::Uuid, mpsc::Sender<Vec<u8>>>>>,
    pub active_ftp_uploads: Arc<Mutex<HashMap<uuid::Uuid, String>>>,

    pub session_keys: Arc<Mutex<HashMap<String, String>>>,

    pub rx_binary_buffers: Arc<Mutex<HashMap<String, Vec<u8>>>>,

    pub peer_max_chunk_size: Arc<std::sync::atomic::AtomicUsize>,
    pub peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,

    pub dc_write_lock: Arc<Mutex<()>>,

    pub negotiation_lock: Arc<Mutex<()>>,
}

impl NodeContext {
    pub fn new(
        outgoing_tx: mpsc::Sender<nodeinnet_p2p::OutboundP2pPayload>,
        log_tx: mpsc::Sender<String>,
        local_event_tx: mpsc::Sender<LocalP2pEvent>,
        my_info: NodeInfo,
        peer_id: String,
        peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
    ) -> Self {
        Self {
            outgoing_tx,
            log_tx,
            local_event_tx,
            my_info,
            peer_id,
            link: lan::Link::Account,
            is_authenticated: Arc::new(AtomicBool::new(false)),
            session_up: Arc::new(AtomicBool::new(false)),
            remote_resources: Arc::new(Mutex::new(HashMap::new())),
            peer_resources: Arc::new(Mutex::new(None)),
            active_downloads: Arc::new(Mutex::new(HashMap::new())),
            requested_downloads: Arc::new(Mutex::new(HashSet::new())),
            unconfirmed_uploads: Arc::new(Mutex::new(HashSet::new())),

            active_terminals: Arc::new(Mutex::new(HashMap::new())),
            active_socks_streams: Arc::new(Mutex::new(HashMap::new())),
            active_ftp_uploads: Arc::new(Mutex::new(HashMap::new())),
            session_keys: Arc::new(Mutex::new(HashMap::new())),
            rx_binary_buffers: Arc::new(Mutex::new(HashMap::new())),
            peer_max_chunk_size: Arc::new(std::sync::atomic::AtomicUsize::new(10240)),
            peer_store,
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
        let mut partial = Vec::new();
        self.active_downloads
            .lock()
            .await
            .retain(|_, download| match download.upload.take() {
                Some(upload) => {
                    partial.push(upload.temp);
                    false
                }
                None => true,
            });
        for temp in partial {
            let _ = tokio::fs::remove_file(temp).await;
        }
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
                | P2pMessage::FileTransferReceipt { .. }
                | P2pMessage::TerminalOutput { .. }
                | P2pMessage::SyncStateResponse { .. }
                | P2pMessage::RemoteDesktopResponse { .. }
                | P2pMessage::HandshakeResponse { .. }
                | P2pMessage::AppListResponse { .. }
                | P2pMessage::AppActionResponse { .. }
        );

        if !is_response {
            if let Some(res_id) = p2p_msg.resource_id() {
                if let Some(resource) = self
                    .my_info
                    .resources
                    .iter()
                    .find(|r| r.id == *res_id && r.is_active)
                {
                    let allowed_types = p2p_msg.allowed_resource_types();
                    if !allowed_types.is_empty() && !allowed_types.contains(&resource.resource_type)
                    {
                        self.log(format!("❌ RBAC Security Violation: a message for resource '{}' is forbidden for resource type {:?}", res_id, resource.resource_type));
                        return;
                    }
                } else {
                    self.log(format!("❌ RBAC Security Violation: Peer attempted to access non-existent or unshared resource '{}'", res_id));
                    return;
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

                my_resources.retain(|r| r.is_active);
                if let Some(req_types) = requested_resources {
                    my_resources.retain(|r| req_types.contains(&r.resource_type));
                }

                for res in my_resources.iter_mut() {
                    let token = nodeinnet_p2p::crypto::generate_session_token();
                    res.session_token = Some(token.clone());
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

    struct NoPeerStore;
    impl nodeinnet_p2p::PeerStore for NoPeerStore {
        fn load(&self) -> HashMap<String, nodeinnet_p2p::PeerConfig> {
            HashMap::new()
        }
        fn update(&self, _: &mut dyn FnMut(&mut HashMap<String, nodeinnet_p2p::PeerConfig>)) {}
    }

    fn make_test_context() -> NodeContext {
        let (outgoing_tx, _) = mpsc::channel(1);
        let (log_tx, _) = mpsc::channel(1);
        let (event_tx, _) = mpsc::channel(1);
        let peers = std::sync::Arc::new(NoPeerStore);
        NodeContext::new(
            outgoing_tx,
            log_tx,
            event_tx,
            make_test_node_info(),
            "test-peer".to_string(),
            peers,
        )
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

    fn sharing_on_and_off() -> (
        NodeContext,
        mpsc::Receiver<nodeinnet_p2p::OutboundP2pPayload>,
        mpsc::Receiver<String>,
    ) {
        let resource = |id: &str, is_active| nodeinnet_p2p::SharedResource {
            id: id.to_string(),
            name: id.to_string(),
            resource_type: nodeinnet_p2p::ResourceType::Filesystem,
            config: None,
            is_active,
            session_token: None,
        };
        let mut info = make_test_node_info();
        info.resources = vec![resource("fs-on", true), resource("fs-off", false)];
        let (outgoing_tx, outgoing_rx) = mpsc::channel(8);
        let (log_tx, log_rx) = mpsc::channel(8);
        let (event_tx, _) = mpsc::channel(1);
        let ctx = NodeContext::new(
            outgoing_tx,
            log_tx,
            event_tx,
            info,
            "test-peer".to_string(),
            std::sync::Arc::new(NoPeerStore),
        );
        (ctx, outgoing_rx, log_rx)
    }

    #[tokio::test]
    async fn a_switched_off_resource_gets_no_token_in_the_handshake() {
        let (ctx, mut outgoing_rx, _log_rx) = sharing_on_and_off();
        ctx.process_message(P2pMessage::Handshake {
            node_version: "1.0".to_string(),
            timestamp_ms: 0,
            signature: String::new(),
            requested_resources: None,
            max_chunk_size: None,
            local_tcp_port: None,
            from_node_id: None,
        })
        .await;

        let Ok(nodeinnet_p2p::OutboundP2pPayload::Message(nodeinnet_p2p::SecuredP2pEnvelope {
            message: P2pMessage::HandshakeResponse { resources },
            ..
        })) = outgoing_rx.try_recv()
        else {
            panic!("no HandshakeResponse");
        };
        let listed: Vec<&str> = resources.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(listed, ["fs-on"]);
        let keys = ctx.session_keys.lock().await;
        assert_eq!(
            keys.keys().map(String::as_str).collect::<Vec<_>>(),
            ["fs-on"]
        );
    }

    #[tokio::test]
    async fn the_server_is_told_what_the_handshake_lists() {
        let (ctx, mut outgoing_rx, _log_rx) = sharing_on_and_off();
        ctx.process_message(P2pMessage::Handshake {
            node_version: "1.0".to_string(),
            timestamp_ms: 0,
            signature: String::new(),
            requested_resources: None,
            max_chunk_size: None,
            local_tcp_port: None,
            from_node_id: None,
        })
        .await;
        let Ok(nodeinnet_p2p::OutboundP2pPayload::Message(nodeinnet_p2p::SecuredP2pEnvelope {
            message: P2pMessage::HandshakeResponse { resources },
            ..
        })) = outgoing_rx.try_recv()
        else {
            panic!("no HandshakeResponse");
        };
        let stored: Vec<_> = resources
            .into_iter()
            .map(|r| nodeinnet_p2p::SharedResource {
                session_token: None,
                ..r
            })
            .collect();
        assert_eq!(
            serde_json::to_string(&ctx.my_info.announced().resources).unwrap(),
            serde_json::to_string(&stored).unwrap()
        );
    }

    #[tokio::test]
    async fn a_request_for_a_switched_off_resource_is_refused() {
        let (ctx, mut outgoing_rx, mut log_rx) = sharing_on_and_off();
        for id in ["fs-on", "fs-off"] {
            ctx.process_message(P2pMessage::RequestEntries {
                request_id: uuid::Uuid::new_v4(),
                resource_id: id.to_string(),
                path: "/".to_string(),
            })
            .await;
        }
        drop(ctx);

        let mut logged = Vec::new();
        while let Some(line) = log_rx.recv().await {
            logged.push(line);
        }
        assert_eq!(logged.len(), 1, "{logged:?}");
        assert!(
            logged[0].contains("RBAC") && logged[0].contains("'fs-off'"),
            "{logged:?}"
        );
        assert!(outgoing_rx.try_recv().is_err());
    }
}
