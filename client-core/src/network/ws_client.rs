use super::manager::NetworkManager;
use super::types::{NetworkMode, PeerBackoff};
use crate::NetCmd;
use futures_util::{SinkExt, StreamExt};
use nodeinnet_p2p::{NodeInfo, WsMessage};
use tokio::sync::mpsc as tokio_mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;

impl NetworkManager {
    pub async fn transition_to_local_mesh_fallback(&mut self, _is_disconnection: bool) {
        self.current_ws_tx = None;
        self.focused_peer = None;
        for task in self.ws_tasks.drain(..) {
            task.abort();
        }

        self.handler
            .on_ws_state_changed(crate::WsState::Disconnected)
            .await;
        self.handler.on_disconnected().await;

        self.mode = NetworkMode::LocalMeshFallback;

        // Trigger direct TCP signaling connections on cached IP addresses
        super::trigger_cached_peer_reconnections(
            self.my_info.id.clone(),
            self.private_key.clone(),
            self.config.clone(),
        );
    }

    pub async fn handle_ws_cmd(&mut self, cmd: NetCmd) {
        match cmd {
            NetCmd::Connect(url, new_my_info, turn) => {
                self.my_info = new_my_info;
                self.current_turn_credentials = turn;
                self.current_ws_url = Some(url.clone());
                for task in self.ws_tasks.drain(..) {
                    task.abort();
                }
                let handler_conn = self.handler.clone();
                handler_conn
                    .on_ws_state_changed(crate::WsState::Connecting)
                    .await;

                self.mode = NetworkMode::WebSocketConnecting;
                self.current_ws_tx = None;

                let conn_fut = connect_async(&url);
                match tokio::time::timeout(std::time::Duration::from_secs(5), conn_fut).await {
                    Ok(Ok((ws_stream, _))) => {
                        handler_conn
                            .on_ws_state_changed(crate::WsState::Connected)
                            .await;
                        handler_conn.on_connected().await;

                        let (mut write, mut read) = ws_stream.split();
                        let (ws_tx, mut ws_rx) = tokio_mpsc::channel::<WsMessage>(32);
                        let _ = ws_tx
                            .send(WsMessage::UpdateNodeInfo(self.my_info.announced()))
                            .await;
                        let _ = ws_tx.send(WsMessage::ListNodes).await;

                        self.current_ws_tx = Some(ws_tx);
                        self.mode = NetworkMode::WebSocketConnected;

                        // mDNS advertiser and scanner continue running in background

                        let _handler_read = handler_conn.clone();
                        let net_tx_read = self.net_tx_bg.clone();

                        let read_task = tokio::spawn(async move {
                            while let Some(Ok(msg)) = read.next().await {
                                if let Message::Text(text) = msg
                                    && let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                                        match ws_msg {
                                            WsMessage::InboundRtcSignal(inbound) => {
                                                let _ = net_tx_read
                                                    .send(NetCmd::HandleInboundSignal(inbound))
                                                    .await;
                                                continue;
                                            }
                                            WsMessage::NodesList { nodes } => {
                                                let _ = net_tx_read
                                                    .send(NetCmd::ProcessNodesList(nodes))
                                                    .await;
                                                continue;
                                            }
                                            _ => {}
                                        }
                                    }
                            }
                            // When disconnected, send Disconnect command to central manager to handle state transition
                            let _ = net_tx_read.send(NetCmd::Disconnect).await;
                        });

                        let write_task = tokio::spawn(async move {
                            let mut interval =
                                tokio::time::interval(std::time::Duration::from_secs(30));
                            loop {
                                tokio::select! {
                                    msg = ws_rx.recv() => {
                                        if let Some(msg) = msg {
                                            if let Ok(json) = serde_json::to_string(&msg) {
                                                let _ = write.send(Message::Text(json)).await;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                    _ = interval.tick() => {
                                        let _ = write.send(Message::Ping(vec![])).await;
                                    }
                                }
                            }
                        });

                        self.ws_tasks.push(read_task);
                        self.ws_tasks.push(write_task);
                    }
                    res => {
                        let _err_msg = match res {
                            Ok(Err(e)) => format!("{}", e),
                            Err(_) => "Timeout".to_string(),
                            _ => unreachable!(),
                        };

                        self.transition_to_local_mesh_fallback(false).await;
                    }
                }
            }
            NetCmd::Disconnect => {
                self.transition_to_local_mesh_fallback(true).await;
            }
            NetCmd::ProcessNodesList(nodes) => {
                self.handler
                    .on_log(format!(
                        "🔌 [WebSocket] Received NodesList from server with {} nodes",
                        nodes.len()
                    ))
                    .await;
                nodeinnet_p2p::update_known_public_keys(&nodes);

                self.config.update(
                    "peers",
                    |map: &mut std::collections::HashMap<String, nodeinnet_p2p::PeerConfig>| {
                        let server_ids: std::collections::HashSet<String> = nodes
                            .iter()
                            .filter(|n| !n.is_temporary)
                            .map(|n| n.id.clone())
                            .collect();

                        map.retain(|id, _| server_ids.contains(id));

                        for n in &nodes {
                            if n.is_temporary {
                                continue;
                            }
                            let entry = map.entry(n.id.clone()).or_default();
                            entry.public_key = n.public_key.clone();
                            entry.name = n.name.clone();
                            entry.os = n.os.clone();
                        }
                    },
                );
                let mut handler_log_for_nodes = "📋 [SIGNALING] Peer list received:\n".to_string();
                for n in &nodes {
                    handler_log_for_nodes.push_str(&format!(
                        "  - {} ({}, OS: {}) Resources: ",
                        n.name, n.id, n.os
                    ));
                    if n.resources.is_empty() {
                        handler_log_for_nodes.push_str("none\n");
                    } else {
                        for r in &n.resources {
                            handler_log_for_nodes
                                .push_str(&format!("{:?} [{}], ", r.resource_type, r.id));
                        }
                        handler_log_for_nodes.push('\n');
                    }
                }
                self.handler.on_log(handler_log_for_nodes).await;

                let mut target_nodes: Vec<&nodeinnet_p2p::NodeInfo> = nodes
                    .iter()
                    .filter(|n| n.app_type != "web" && n.id > self.my_info.id && n.is_online)
                    .collect();
                target_nodes.sort_by(|a, b| a.id.cmp(&b.id));

                let active_ids: Vec<String> = self.active_peers.keys().cloned().collect();
                for active_id in active_ids {
                    if !nodes.iter().any(|n| n.id == active_id) {
                        if let Some(peer) = self.active_peers.remove(&active_id) {
                            let pc = peer.peer_connection.clone();
                            drop(peer);
                            let _peer_id = active_id.clone();
                            tokio::spawn(async move {
                                let _ = pc.close().await;
                            });
                        }
                        if self.focused_peer == Some(active_id.clone()) {
                            self.focused_peer = None;
                        }

                        let backoff =
                            self.backoff_states
                                .entry(active_id.clone())
                                .or_insert_with(|| PeerBackoff {
                                    attempt_count: 0,
                                    last_attempt: std::time::Instant::now(),
                                    is_connected: false,
                                });
                        if backoff.is_connected {
                            backoff.is_connected = false;
                            backoff.attempt_count = 1;
                            backoff.last_attempt = std::time::Instant::now();
                        } else {
                            backoff.last_attempt = std::time::Instant::now();
                        }
                    }
                }

                for node in &nodes {
                    if let Some(old_info) = self.last_known_nodes.get(&node.id) {
                        if !old_info.is_online && node.is_online
                            && let Some(backoff) = self.backoff_states.get_mut(&node.id) {
                                backoff.attempt_count = 0;
                                backoff.is_connected = false;
                            }

                        if let (Ok(old_res), Ok(new_res)) = (
                            serde_json::to_string(&old_info.resources),
                            serde_json::to_string(&node.resources),
                        ) && old_res != new_res
                            && self.active_peers.contains_key(&node.id) {
                                if let Some(peer) = self.active_peers.remove(&node.id) {
                                    let pc = peer.peer_connection.clone();
                                    drop(peer);
                                    let _peer_id = node.id.clone();
                                    tokio::spawn(async move {
                                        let _ = pc.close().await;
                                    });
                                }
                                if self.focused_peer == Some(node.id.clone()) {
                                    self.focused_peer = None;
                                }

                                let tx = self.net_tx_bg.clone();
                                let target_id = node.id.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                    let _ = tx.send(NetCmd::Call(target_id)).await;
                                });
                            }
                    }

                    if node.app_type != "web" && node.id > self.my_info.id && node.is_online {
                        let position = target_nodes
                            .iter()
                            .position(|n| n.id == node.id)
                            .unwrap_or(0);
                        let delay_ms = (position as u64) * 300;

                        let tx = self.net_tx_bg.clone();
                        let target_id = node.id.clone();
                        tokio::spawn(async move {
                            if delay_ms > 0 {
                                tokio::time::sleep(std::time::Duration::from_millis(delay_ms))
                                    .await;
                            }
                            let _ = tx.send(NetCmd::AutoConnect(target_id)).await;
                        });
                    }

                    self.last_known_nodes.insert(node.id.clone(), node.clone());
                }

                self.last_known_nodes.retain(|id, node| {
                    let in_server_list = nodes.iter().any(|n| n.id == *id);
                    if in_server_list {
                        return true;
                    }
                    let locally_connected = {
                        if let Some(tunnels) = p2p_node::local_mesh::ACTIVE_TCP_TUNNELS.get() {
                            if let Ok(guard) = tunnels.try_lock() {
                                guard.contains_key(id)
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };
                    if locally_connected {
                        node.is_online = true;
                        return true;
                    }
                    false
                });

                let all_nodes: Vec<NodeInfo> = self.last_known_nodes.values().cloned().collect();
                let _ = self.handler.on_update_nodes(all_nodes).await;
            }
            NetCmd::ReloadResources(resources) => {
                self.my_info.resources = resources;
                if let Some(tx) = &self.current_ws_tx {
                    let _ = tx
                        .send(WsMessage::UpdateNodeInfo(self.my_info.announced()))
                        .await;
                }

                for (_id, peer) in self.active_peers.drain() {
                    let pc = peer.peer_connection.clone();
                    drop(peer);
                    tokio::spawn(async move {
                        let _ = pc.close().await;
                    });
                }
                self.focused_peer = None;
            }
            NetCmd::UpdateName(name) => {
                self.my_info.name = name;
                // Reconnect with the new name: the server re-registers us and pushes a
                // fresh NodesList to peers, so they see the new name without an app restart.
                if let Some(url) = self.current_ws_url.clone() {
                    let _ = self
                        .net_tx_bg
                        .send(NetCmd::Connect(
                            url,
                            self.my_info.clone(),
                            self.current_turn_credentials.clone(),
                        ))
                        .await;
                }
            }
            _ => {}
        }
    }
}
