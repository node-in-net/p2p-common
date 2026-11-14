use super::types::{NetworkMode, PeerBackoff};
use crate::{AppEventHandler, NetCmd};
use nodeinnet_p2p::NodeInfo;
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
    pub net_tx_bg: tokio_mpsc::UnboundedSender<NetCmd>,
    pub lan: Option<Arc<p2p_node::lan::Lan>>,
    pub lan_resources: Vec<nodeinnet_p2p::SharedResource>,
    pub lan_dials: std::collections::HashMap<String, u64>,
    pub peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
}

impl NetworkManager {
    pub fn new(
        my_info: NodeInfo,
        private_key: String,
        handler: Arc<dyn AppEventHandler>,
        net_tx_bg: tokio_mpsc::UnboundedSender<NetCmd>,
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
            lan: None,
            lan_resources: Vec::new(),
            lan_dials: std::collections::HashMap::new(),
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
            | NetCmd::Call(..) => {
                self.handle_peer_cmd(cmd).await;
            }
            NetCmd::Send(..)
            | NetCmd::SendP2p(..)
            | NetCmd::SendP2pMessage(..)
            | NetCmd::SendToPeer(..)
            | NetCmd::BroadcastP2pMessage { .. } => {
                self.handle_p2p_cmd(cmd).await;
            }
            NetCmd::Lan(cmd) => self.handle_lan_cmd(cmd).await,
            NetCmd::SendLanSignal(id, signal) => self.send_lan_signal(&id, signal).await,
            NetCmd::LanSessionUp(id, connection_id, resources) => {
                self.handle_lan_session_up(id, connection_id, resources)
                    .await
            }
            NetCmd::Shutdown => self.shutdown().await,
        }
    }

    pub async fn shutdown(&mut self) {
        self.current_ws_tx = None;
        for task in self.ws_tasks.drain(..) {
            task.abort();
        }
        let closing: Vec<_> = self.active_peers.drain().map(|(_, peer)| peer).collect();
        let lan = self.lan.take();
        let stopping = async move {
            if let Some(lan) = lan {
                lan.stop().await;
            }
        };
        let _ = tokio::join!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                futures_util::future::join_all(closing.iter().map(|peer| async move {
                    peer.end_session().await;
                    let _ = peer.peer_connection.close().await;
                })),
            ),
            stopping,
        );
    }
}
