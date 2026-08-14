use super::manager::NetworkManager;
use crate::{AppEventHandler, NetCmd};
use nodeinnet_p2p::rtc::{RtcSignal, RtcSignalEnvelope};
use nodeinnet_p2p::{P2pMessage, WsMessage};

impl NetworkManager {
    pub async fn handle_p2p_cmd(&mut self, cmd: NetCmd) {
        match cmd {
            NetCmd::Send(msg) => {
                if let WsMessage::RtcSignal(envelope) = msg {
                    let signal_name = match &envelope.signal {
                        RtcSignal::Offer { .. } => "Offer",
                        RtcSignal::Answer { .. } => "Answer",
                        RtcSignal::IceCandidate { .. } => "IceCandidate",
                    };
                    self.handler
                        .on_log(format!(
                            "📤 [network.rs] Received NetCmd::Send for RTC {} to {}",
                            signal_name, envelope.to_node_id
                        ))
                        .await;
                    let current_ws = self.current_ws_tx.clone();
                    let handler_route = self.handler.clone();
                    tokio::spawn(async move {
                        super::route_rtc_signal(envelope, &current_ws, &handler_route).await;
                    });
                } else {
                    if let Some(tx) = &self.current_ws_tx {
                        let _ = tx.send(msg).await;
                    } else {
                        self.handler.on_log("⚠️ Not connected!".to_string()).await;
                    }
                }
            }
            NetCmd::SendP2p(text) => {
                if let Some(focused) = &self.focused_peer {
                    if let Some(rtc) = self.active_peers.get(focused) {
                        let p2p_msg = P2pMessage::TextMessage { text: text.clone() };
                        if let Err(e) = rtc.send_p2p_message(p2p_msg).await {
                            self.handler
                                .on_log(format!("❌ Failed to send P2P: {}", e))
                                .await;
                        } else {
                            self.handler
                                .on_log(format!("📤 Sent P2P to {}: {}", focused, text))
                                .await;
                        }
                    }
                } else {
                    self.handler
                        .on_log("⚠️ No focused peer for SendP2p!".to_string())
                        .await;
                }
            }
            NetCmd::SendP2pMessage(msg) => {
                if let Some(focused) = &self.focused_peer
                    && let Some(rtc) = self.active_peers.get(focused)
                    && let Err(e) = rtc.send_p2p_message(msg).await
                {
                    self.handler
                        .on_log(format!("❌ Failed to send P2P: {}", e))
                        .await;
                }
            }
            NetCmd::SendToPeer(node_id, msg) => {
                if let Some(rtc) = self.active_peers.get(&node_id) {
                    let _ = rtc.send_p2p_message(msg).await;
                }
            }
            NetCmd::BroadcastP2pMessage {
                target_resource_type,
                msg_template,
            } => {
                for (id, rtc) in self.active_peers.iter() {
                    if let Some(target_id) = rtc.get_remote_resource_id(&target_resource_type).await
                    {
                        let mut specialized_msg = msg_template.clone();
                        specialized_msg.set_resource_id(target_id);

                        if let Err(e) = rtc.send_p2p_message(specialized_msg).await {
                            self.handler
                                .on_log(format!("❌ Failed to broadcast to {}: {}", id, e))
                                .await;
                        }
                    }
                }
            }
            NetCmd::RegisterUpload {
                peer_id,
                transfer_id,
                local_file_path,
            } => {
                if let Some(rtc) = self.active_peers.get(&peer_id) {
                    rtc.node_context
                        .active_uploads
                        .lock()
                        .await
                        .insert(transfer_id, local_file_path);
                }
            }
            _ => {}
        }
    }
}
