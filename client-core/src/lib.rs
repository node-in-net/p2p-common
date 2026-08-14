pub mod auth;
#[cfg(feature = "feature-rdesk")]
pub mod desktop;
pub mod network;
pub mod rtc;

use async_trait::async_trait;
use nodeinnet_p2p::rtc::InboundRtcSignal;
use nodeinnet_p2p::{NodeInfo, P2pMessage, WsMessage};
use std::path::PathBuf;

pub enum NetCmd {
    Connect(
        String,
        NodeInfo,
        Option<nodeinnet_p2p::rtc::TurnCredentials>,
    ),
    Disconnect,
    DisconnectPeer(String),
    DisconnectPeerSession(String, uuid::Uuid),
    Send(WsMessage),
    SendP2p(String),
    SendP2pMessage(P2pMessage),
    SendToPeer(String, P2pMessage),
    BroadcastP2pMessage {
        target_resource_type: nodeinnet_p2p::p2p::ResourceType,
        msg_template: P2pMessage,
    },
    HandleInboundSignal(InboundRtcSignal),
    RegisterUpload {
        peer_id: String,
        transfer_id: uuid::Uuid,
        local_file_path: PathBuf,
    },
    Call(String),
    AutoConnect(String),
    PeerConnected(String, Vec<nodeinnet_p2p::SharedResource>),
    ReloadResources(Vec<nodeinnet_p2p::SharedResource>),
    /// Change the announced display name without a reconnect: updates `my_info.name`,
    /// re-announces the NodeInfo to the signaling server, and re-advertises mDNS.
    UpdateName(String),
    ProcessNodesList(Vec<NodeInfo>),
    MergeNodesList(Vec<NodeInfo>),
    SetLocalDiscovery(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WsState {
    Disconnected,
    Connecting,
    Connected,
    LocalMesh,
    LocalMeshError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum P2pPeerState {
    Disconnected,
    ConnectingTransport,
    Authenticating,
    Connected,
    Failed,
}

#[async_trait]
pub trait AppEventHandler: Send + Sync + 'static {
    async fn on_log(&self, msg: String);
    async fn on_connected(&self);
    async fn on_disconnected(&self);
    async fn on_update_nodes(&self, nodes: Vec<NodeInfo>);
    async fn on_download_complete(&self, path: PathBuf);

    // State machine updates
    async fn on_ws_state_changed(&self, _state: WsState) {}
    async fn on_peer_state_changed(&self, _peer_id: String, _state: P2pPeerState) {}

    async fn on_p2p_message(&self, msg: P2pMessage);
    async fn on_p2p_connecting(&self, _peer_id: String) {}
    async fn on_p2p_connected(&self, peer_id: String);
    async fn on_p2p_disconnected(&self, peer_id: String);
    async fn on_p2p_ping_updated(&self, _peer_id: String, _rtt_ms: u64) {}
    async fn on_peer_connection_type_changed(&self, _peer_id: String, _connection_type: String) {}

    async fn on_local_p2p_event(&self, _event: p2p_node::LocalP2pEvent) {}
}
