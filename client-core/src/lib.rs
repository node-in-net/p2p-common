pub mod auth;
#[cfg(feature = "feature-rdesk")]
pub mod desktop;
pub mod launcher;
pub mod limits;
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
    ApplyTurnCredentials(Option<nodeinnet_p2p::rtc::TurnCredentials>),
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

#[derive(Debug, Clone)]
pub enum P2pFailure {
    Transport(String),
    ClockSkew { ahead_ms: u64 },
    BadSignature(String),
    UnknownKey,
    MissingHmac { resource: String },
    BadHmac { resource: String },
    NoSessionKey { resource: String },
    Unauthenticated,
    OfferFailed(String),
    ClientInitFailed(String),
}

impl std::fmt::Display for P2pFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(s) => write!(
                f,
                "WebRTC transport failed ({s}) — ICE could not connect; check the firewall and TURN"
            ),
            Self::ClockSkew { ahead_ms } => write!(
                f,
                "handshake rejected: local clock is {ahead_ms} ms past the peer's — sync system time"
            ),
            Self::BadSignature(e) => write!(f, "handshake signature rejected: {e}"),
            Self::UnknownKey => write!(
                f,
                "no trusted public key for this peer after 5 s — is it registered on the account?"
            ),
            Self::MissingHmac { resource } => {
                write!(f, "command for `{resource}` carried no HMAC — blocked")
            }
            Self::BadHmac { resource } => {
                write!(f, "invalid HMAC for `{resource}` — blocked")
            }
            Self::NoSessionKey { resource } => {
                write!(f, "no session key for `{resource}` — blocked")
            }
            Self::Unauthenticated => {
                write!(f, "peer sent commands before authenticating — blocked")
            }
            Self::OfferFailed(e) => write!(f, "could not create the WebRTC offer: {e}"),
            Self::ClientInitFailed(e) => write!(f, "could not start the WebRTC client: {e}"),
        }
    }
}

#[async_trait]
pub trait AppEventHandler: Send + Sync + 'static {
    async fn on_log(&self, msg: String);
    async fn on_connected(&self);
    async fn on_disconnected(&self);
    async fn on_update_nodes(&self, nodes: Vec<NodeInfo>);
    async fn on_download_complete(&self, path: PathBuf);

    async fn on_ws_state_changed(&self, _state: WsState) {}
    async fn on_peer_state_changed(&self, _peer_id: String, _state: P2pPeerState) {}
    async fn on_peer_failed(&self, _peer_id: String, _failure: P2pFailure) {}

    async fn on_p2p_message(&self, msg: P2pMessage);
    async fn on_p2p_connecting(&self, _peer_id: String) {}
    async fn on_p2p_connected(&self, peer_id: String);
    async fn on_p2p_disconnected(&self, peer_id: String);
    async fn on_p2p_ping_updated(&self, _peer_id: String, _rtt_ms: u64) {}
    async fn on_peer_connection_type_changed(&self, _peer_id: String, _connection_type: String) {}

    async fn on_local_p2p_event(&self, _event: p2p_node::LocalP2pEvent) {}
}

#[cfg(test)]
mod failure_tests {
    use super::P2pFailure;

    #[test]
    fn the_measured_skew_reaches_the_message() {
        let text = P2pFailure::ClockSkew { ahead_ms: 91_500 }.to_string();
        assert!(text.contains("91500"), "{text}");
    }

    #[test]
    fn the_transport_state_reaches_the_message() {
        let text = P2pFailure::Transport("Failed".into()).to_string();
        assert!(text.contains("Failed"), "{text}");
    }

    #[test]
    fn a_blocked_resource_is_named() {
        let text = P2pFailure::BadHmac {
            resource: "fs-root".into(),
        }
        .to_string();
        assert!(text.contains("fs-root"), "{text}");
    }
}
