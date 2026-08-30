use super::types::{NetworkMode, PeerBackoff};
use crate::{AppEventHandler, NetCmd};
use nodeinnet_p2p::NodeInfo;
use p2p_node::local_mesh::LocalMeshSignal;
use std::sync::Arc;
use tokio::sync::mpsc as tokio_mpsc;

pub struct NetworkManager {
    pub mode: NetworkMode,
    pub my_info: NodeInfo,
    pub private_key: String,
    pub current_ws_tx: Option<tokio_mpsc::Sender<nodeinnet_p2p::WsMessage>>,
    pub ws_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub active_peers: std::collections::HashMap<String, crate::rtc::WebRtcClient>,
    pub backoff_states: std::collections::HashMap<String, PeerBackoff>,
    pub focused_peer: Option<String>,
    pub last_known_nodes: std::collections::HashMap<String, NodeInfo>,
    pub current_turn_credentials: Option<nodeinnet_p2p::rtc::TurnCredentials>,
    pub current_ws_url: Option<String>,
    pub handler: Arc<dyn AppEventHandler>,
    pub net_tx_bg: tokio_mpsc::Sender<NetCmd>,
    pub local_discovery_enabled: bool,
    pub local_discovery_started: bool,
    pub peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
}

impl NetworkManager {
    pub fn new(
        my_info: NodeInfo,
        private_key: String,
        handler: Arc<dyn AppEventHandler>,
        net_tx_bg: tokio_mpsc::Sender<NetCmd>,
        peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
    ) -> Self {
        Self {
            mode: NetworkMode::WebSocketConnecting,
            my_info,
            private_key,
            current_ws_tx: None,
            ws_tasks: Vec::new(),
            active_peers: std::collections::HashMap::new(),
            backoff_states: std::collections::HashMap::new(),
            focused_peer: None,
            last_known_nodes: std::collections::HashMap::new(),
            current_turn_credentials: None,
            current_ws_url: None,
            handler,
            net_tx_bg,
            local_discovery_enabled: false,
            local_discovery_started: false,
            peer_store,
        }
    }

    pub async fn handle_net_cmd(&mut self, cmd: NetCmd) {
        match cmd {
            NetCmd::Connect(..)
            | NetCmd::ApplyTurnCredentials(..)
            | NetCmd::Disconnect
            | NetCmd::ProcessNodesList(..)
            | NetCmd::ReloadResources(..)
            | NetCmd::UpdateName(..) => {
                self.handle_ws_cmd(cmd).await;
            }
            NetCmd::DisconnectPeer(..)
            | NetCmd::DisconnectPeerSession(..)
            | NetCmd::PeerConnected(..)
            | NetCmd::HandleInboundSignal(..)
            | NetCmd::AutoConnect(..)
            | NetCmd::Call(..)
            | NetCmd::MergeNodesList(..) => {
                self.handle_peer_cmd(cmd).await;
            }
            NetCmd::Send(..)
            | NetCmd::SendP2p(..)
            | NetCmd::SendP2pMessage(..)
            | NetCmd::SendToPeer(..)
            | NetCmd::BroadcastP2pMessage { .. }
            | NetCmd::RegisterUpload { .. } => {
                self.handle_p2p_cmd(cmd).await;
            }
            NetCmd::SetLocalDiscovery(enabled) => {
                self.local_discovery_enabled = enabled;
                if enabled {
                    self.start_local_discovery();
                }
            }
        }
    }

    pub fn start_local_discovery(&mut self) {
        if self.local_discovery_started {
            return;
        }
        self.local_discovery_started = true;
        self.local_discovery_enabled = true;

        let my_id_local = self.my_info.id.clone();
        let pub_key_local = self.my_info.public_key.clone();
        let priv_key_local = self.private_key.clone();
        let my_name_local = self.my_info.name.clone();
        let my_os_local = self.my_info.os.clone();
        let handler_local = self.handler.clone();
        let peer_store_local = self.peer_store.clone();

        tokio::spawn(async move {
            match p2p_node::local_mesh::start_tcp_signaling_server(
                my_id_local.clone(),
                priv_key_local.clone(),
                peer_store_local.clone(),
            )
            .await
            {
                Ok(port) => {
                    let _ = p2p_node::mdns_discovery::start_mdns_advertiser(
                        &my_id_local,
                        &pub_key_local,
                        &priv_key_local,
                        port,
                        &my_name_local,
                        &my_os_local,
                    );
                }
                Err(e) => {
                    let _ = handler_local
                        .on_log(format!("❌ Failed to start TCP signaling server: {}", e))
                        .await;
                    let _ = handler_local
                        .on_ws_state_changed(crate::WsState::LocalMeshError)
                        .await;
                }
            }
            let _ = p2p_node::mdns_discovery::start_mdns_scanner(
                my_id_local,
                priv_key_local,
                peer_store_local,
            );
        });
    }

    pub async fn handle_local_mesh_signal(&mut self, signal: LocalMeshSignal) {
        self.handle_peer_signal(signal).await;
    }
}
