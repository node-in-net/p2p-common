pub mod lan;
pub mod manager;
pub mod p2p_transfer;
pub mod peer_orchestrator;
pub mod types;
pub mod ws_client;

pub use manager::NetworkManager;
pub use types::{NetworkMode, PeerBackoff};

use crate::{AppEventHandler, NetCmd};
use futures_util::FutureExt;
use nodeinnet_p2p::rtc::{RtcSignal, RtcSignalEnvelope};
use nodeinnet_p2p::{NodeInfo, WsMessage};
use std::collections::VecDeque;
use std::sync::Arc;
use std::thread;
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;

const QUEUED: usize = 16;

pub async fn route_rtc_signal(
    envelope: RtcSignalEnvelope,
    current_ws_tx: &Option<tokio_mpsc::Sender<WsMessage>>,
    handler: &Arc<dyn AppEventHandler>,
) {
    let signal_name = match &envelope.signal {
        RtcSignal::Offer { .. } => "Offer",
        RtcSignal::Answer { .. } => "Answer",
        RtcSignal::IceCandidate { .. } => "IceCandidate",
    };

    if let Some(tx) = current_ws_tx {
        let _ = handler
            .on_log(format!(
                "📡 [route_rtc_signal] Routing RTC {} over Cloud WS to {}",
                signal_name, envelope.to_node_id
            ))
            .await;
        let _ = tx.send(WsMessage::RtcSignal(envelope)).await;
    } else {
        let _ = handler
            .on_log(format!(
                "⚠️ Failed to route RtcSignal {} to {}: offline",
                signal_name, envelope.to_node_id
            ))
            .await;
    }
}

pub fn start_network_thread(
    net_rx: tokio_mpsc::Receiver<NetCmd>,
    net_tx: tokio_mpsc::Sender<NetCmd>,
    handler: Arc<dyn AppEventHandler>,
    my_info: NodeInfo,
    private_key: String,
    peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
    lan: Option<p2p_node::lan::LanConfig>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let rt = match Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = handler
                    .on_log(format!(
                        "❌ [Network] Could not start the network runtime: {}",
                        e
                    ))
                    .now_or_never();
                return;
            }
        };
        rt.block_on(run_network_manager(
            net_rx,
            net_tx,
            handler,
            my_info,
            private_key,
            peer_store,
            lan,
        ));
        rt.shutdown_timeout(std::time::Duration::from_secs(1));
    })
}

pub async fn run_network_manager(
    mut net_rx: tokio_mpsc::Receiver<NetCmd>,
    _net_tx: tokio_mpsc::Sender<NetCmd>,
    handler: Arc<dyn AppEventHandler>,
    my_info: NodeInfo,
    private_key: String,
    peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
    lan: Option<p2p_node::lan::LanConfig>,
) {
    let (bg_tx, mut bg_rx) = tokio_mpsc::unbounded_channel();
    let mut manager = NetworkManager::new(
        my_info,
        private_key.clone(),
        handler.clone(),
        bg_tx,
        peer_store.clone(),
    );

    let peers: std::collections::HashMap<String, nodeinnet_p2p::PeerConfig> = peer_store.load();
    let mut cached_peers_log = format!(
        "📁 Loaded {} cached peers from the host store on startup:\n",
        peers.len()
    );
    for (id, peer) in &peers {
        cached_peers_log.push_str(&format!("  - {} ({}, OS: {})\n", peer.name, id, peer.os));
    }
    let _ = manager.handler.on_log(cached_peers_log).await;
    let mut initial_nodes = Vec::new();
    for (id, peer) in peers {
        if id == manager.my_info.id {
            continue;
        }
        if peer.os == "web" || peer.name == "Web Browser Node" {
            continue;
        }
        initial_nodes.push(NodeInfo {
            id: id.clone(),
            name: peer.name,
            os: peer.os,
            version: "0.1.0".to_string(),
            app_type: "desktop".to_string(),
            build_type: "debug".to_string(),
            public_key: peer.public_key,
            resources: vec![],
            is_online: false,
            last_used: 0,
            is_temporary: false,
        });
    }
    if !initial_nodes.is_empty() {
        nodeinnet_p2p::update_known_public_keys(&initial_nodes);
        for node in &initial_nodes {
            manager
                .last_known_nodes
                .insert(node.id.clone(), node.clone());
        }
        let all_nodes: Vec<NodeInfo> = manager.last_known_nodes.values().cloned().collect();
        let _ = manager.handler.on_update_nodes(all_nodes).await;
    }

    let (lan_tx, mut lan_rx) = tokio_mpsc::channel(256);
    let mut lan_open = match lan {
        Some(config) => manager.start_lan(config, lan_tx).await,
        None => false,
    };

    let mut reconnect_interval = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut later = VecDeque::new();

    loop {
        let stop = tokio::select! {
            Some(cmd) = async { later.pop_front() } => {
                until_shutdown(
                    manager.handle_net_cmd(cmd),
                    &mut net_rx,
                    &mut bg_rx,
                    &mut later,
                )
                .await
            }
            _ = reconnect_interval.tick() => {
                until_shutdown(manager.handle_tick(), &mut net_rx, &mut bg_rx, &mut later).await
            }
            Some(cmd) = bg_rx.recv(), if later.is_empty() => {
                until_shutdown(
                    manager.handle_net_cmd(cmd),
                    &mut net_rx,
                    &mut bg_rx,
                    &mut later,
                )
                .await
            }
            cmd_opt = net_rx.recv(), if later.is_empty() => {
                match cmd_opt {
                    Some(NetCmd::Shutdown) => true,
                    Some(cmd) => {
                        until_shutdown(
                            manager.handle_net_cmd(cmd),
                            &mut net_rx,
                            &mut bg_rx,
                            &mut later,
                        )
                        .await
                    }
                    None => {
                        manager.shutdown().await;
                        break;
                    }
                }
            }
            signal_opt = lan_rx.recv(), if lan_open => {
                match signal_opt {
                    Some(signal) => {
                        until_shutdown(
                            manager.handle_lan_signal(signal),
                            &mut net_rx,
                            &mut bg_rx,
                            &mut later,
                        )
                        .await
                    }
                    None => {
                        lan_open = false;
                        false
                    }
                }
            }
        };
        if stop {
            manager.shutdown().await;
            break;
        }
    }
}

async fn until_shutdown(
    work: impl Future<Output = ()>,
    net_rx: &mut tokio_mpsc::Receiver<NetCmd>,
    bg_rx: &mut tokio_mpsc::UnboundedReceiver<NetCmd>,
    later: &mut VecDeque<NetCmd>,
) -> bool {
    tokio::pin!(work);
    let mut open = true;
    loop {
        tokio::select! {
            _ = &mut work => return false,
            Some(cmd) = bg_rx.recv() => later.push_back(cmd),
            cmd = net_rx.recv(), if open && later.len() < QUEUED => match cmd {
                Some(NetCmd::Shutdown) => return true,
                Some(cmd) => later.push_back(cmd),
                None => open = false,
            },
        }
    }
}

pub fn spawn_network_task(
    net_rx: tokio_mpsc::Receiver<NetCmd>,
    net_tx: tokio_mpsc::Sender<NetCmd>,
    handler: Arc<dyn AppEventHandler>,
    my_info: NodeInfo,
    private_key: String,
    peer_store: std::sync::Arc<dyn nodeinnet_p2p::PeerStore>,
    lan: Option<p2p_node::lan::LanConfig>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_network_manager(
        net_rx,
        net_tx,
        handler,
        my_info,
        private_key,
        peer_store,
        lan,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodeinnet_p2p::{MemoryPeerStore, P2pMessage, PeerConfig, PeerStore};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct Quiet {
        dialled: AtomicUsize,
        disconnected: AtomicUsize,
        receipts: std::sync::Mutex<Vec<(uuid::Uuid, bool)>>,
    }

    #[async_trait::async_trait]
    impl AppEventHandler for Quiet {
        async fn on_log(&self, _msg: String) {}
        async fn on_connected(&self) {}
        async fn on_disconnected(&self) {
            self.disconnected.fetch_add(1, Ordering::SeqCst);
        }
        async fn on_update_nodes(&self, _nodes: Vec<NodeInfo>) {}
        async fn on_download_complete(&self, _path: std::path::PathBuf) {}
        async fn on_p2p_message(&self, msg: P2pMessage) {
            if let P2pMessage::FileTransferReceipt {
                transfer_id,
                result,
            } = msg
            {
                self.receipts
                    .lock()
                    .unwrap()
                    .push((transfer_id, result.is_ok()));
            }
        }
        async fn on_p2p_connecting(&self, _peer_id: String) {
            self.dialled.fetch_add(1, Ordering::SeqCst);
        }
        async fn on_p2p_connected(&self, _peer_id: String) {}
        async fn on_p2p_disconnected(&self, _peer_id: String) {}
    }

    #[derive(Default)]
    struct Cache {
        peers: MemoryPeerStore,
        reads: AtomicUsize,
    }

    impl PeerStore for Cache {
        fn load(&self) -> HashMap<String, PeerConfig> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.peers.load()
        }

        fn update(&self, f: &mut dyn FnMut(&mut HashMap<String, PeerConfig>)) {
            self.peers.update(f)
        }
    }

    struct Gate {
        open: tokio::sync::Semaphore,
        held: AtomicUsize,
        redials: std::sync::Mutex<Vec<String>>,
        dropped: AtomicUsize,
    }

    impl Gate {
        fn shut() -> Arc<Self> {
            Arc::new(Self {
                open: tokio::sync::Semaphore::new(0),
                held: AtomicUsize::new(0),
                redials: std::sync::Mutex::new(Vec::new()),
                dropped: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl AppEventHandler for Gate {
        async fn on_log(&self, msg: String) {
            if msg.contains("[TURN]") {
                self.redials.lock().unwrap().push(msg);
                self.held.fetch_add(1, Ordering::SeqCst);
                let _ = self.open.acquire().await;
            }
        }
        async fn on_connected(&self) {}
        async fn on_disconnected(&self) {}
        async fn on_update_nodes(&self, _nodes: Vec<NodeInfo>) {}
        async fn on_download_complete(&self, _path: std::path::PathBuf) {}
        async fn on_p2p_message(&self, _msg: P2pMessage) {}
        async fn on_p2p_connected(&self, _peer_id: String) {}
        async fn on_p2p_disconnected(&self, _peer_id: String) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn held_network(
        gate: &Arc<Gate>,
        room: usize,
    ) -> (tokio_mpsc::Sender<NetCmd>, tokio::task::JoinHandle<()>) {
        let (net_tx, net_rx) = tokio_mpsc::channel(room);
        let task = spawn_network_task(
            net_rx,
            net_tx.clone(),
            gate.clone(),
            node("aa-me"),
            String::new(),
            Arc::new(MemoryPeerStore::default()),
            None,
        );
        (net_tx, task)
    }

    fn chunk() -> NetCmd {
        NetCmd::SendToPeer("nobody".to_string(), P2pMessage::Ping(0))
    }

    async fn until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn fill(net_tx: &tokio_mpsc::Sender<NetCmd>) -> usize {
        let mut taken = 0;
        loop {
            let before = taken;
            while taken < 1024 && net_tx.try_send(chunk()).is_ok() {
                taken += 1;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            if taken == before || taken == 1024 {
                return taken;
            }
        }
    }

    #[derive(Default)]
    struct Upload {
        chunks: AtomicUsize,
        lan_events: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl AppEventHandler for Upload {
        async fn on_log(&self, msg: String) {
            if msg.contains("No focused peer") {
                self.chunks.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        async fn on_connected(&self) {}
        async fn on_disconnected(&self) {}
        async fn on_update_nodes(&self, _nodes: Vec<NodeInfo>) {}
        async fn on_download_complete(&self, _path: std::path::PathBuf) {}
        async fn on_p2p_message(&self, _msg: P2pMessage) {}
        async fn on_p2p_connected(&self, _peer_id: String) {}
        async fn on_p2p_disconnected(&self, _peer_id: String) {}
        async fn on_lan_event(&self, _event: p2p_node::lan::LanEvent) {
            self.lan_events.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct NoTrust;

    impl p2p_node::lan::TrustStore for NoTrust {
        fn load(&self) -> std::io::Result<Option<String>> {
            Ok(None)
        }

        fn save(&self, _doc: &str) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn node(id: &str) -> NodeInfo {
        NodeInfo {
            id: id.to_string(),
            name: id.to_string(),
            os: "linux".to_string(),
            version: "0.0.0".to_string(),
            app_type: "desktop".to_string(),
            build_type: "debug".to_string(),
            public_key: String::new(),
            resources: vec![],
            is_online: false,
            last_used: 0,
            is_temporary: false,
        }
    }

    #[test]
    fn shutdown_ends_the_network_thread() {
        let (net_tx, net_rx) = tokio_mpsc::channel(8);
        let thread = start_network_thread(
            net_rx,
            net_tx.clone(),
            Arc::new(Quiet::default()),
            node("shutdown-thread"),
            String::new(),
            Arc::new(MemoryPeerStore::default()),
            None,
        );
        net_tx
            .blocking_send(NetCmd::Shutdown)
            .expect("the network loop is listening");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !thread.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(thread.is_finished(), "the network thread outlived Shutdown");
        thread.join().expect("the network thread panicked");
    }

    #[test]
    fn shutdown_does_not_wait_for_a_connect_in_flight() {
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let url = format!("ws://{}/ws", server.local_addr().expect("its address"));
        let (net_tx, net_rx) = tokio_mpsc::channel(8);
        let thread = start_network_thread(
            net_rx,
            net_tx.clone(),
            Arc::new(Quiet::default()),
            node("shutdown-connect"),
            String::new(),
            Arc::new(MemoryPeerStore::default()),
            None,
        );
        net_tx
            .blocking_send(NetCmd::Connect(url, node("shutdown-connect"), None))
            .expect("the network loop is listening");
        let (_silent, _) = server.accept().expect("the connect reached the server");

        let started = Instant::now();
        net_tx
            .blocking_send(NetCmd::Shutdown)
            .expect("the network loop is listening");
        while !thread.is_finished() && started.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "Shutdown waited {:?} for the connect",
            started.elapsed()
        );
        thread.join().expect("the network thread panicked");
    }

    fn accept_within(
        server: &std::net::TcpListener,
        wait: Duration,
    ) -> Option<std::net::TcpStream> {
        server
            .set_nonblocking(true)
            .expect("a non-blocking listener");
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if let Ok((socket, _)) = server.accept() {
                return Some(socket);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    #[test]
    fn a_connect_queued_behind_another_runs_next_and_still_yields_to_shutdown() {
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let url = format!("ws://{}/ws", server.local_addr().expect("its address"));
        let handler = Arc::new(Quiet::default());
        let (net_tx, net_rx) = tokio_mpsc::channel(8);
        let thread = start_network_thread(
            net_rx,
            net_tx.clone(),
            handler.clone(),
            node("two-connects"),
            String::new(),
            Arc::new(MemoryPeerStore::default()),
            None,
        );
        for _ in 0..2 {
            net_tx
                .blocking_send(NetCmd::Connect(url.clone(), node("two-connects"), None))
                .expect("the network loop is listening");
        }
        let first = accept_within(&server, Duration::from_secs(5))
            .expect("the first connect reached the server");
        std::thread::sleep(Duration::from_millis(200));
        drop(first);
        let _second = accept_within(&server, Duration::from_secs(5))
            .expect("the queued connect ran once the first one failed");
        assert_eq!(handler.disconnected.load(Ordering::SeqCst), 1);

        let started = Instant::now();
        net_tx
            .blocking_send(NetCmd::Shutdown)
            .expect("the network loop is listening");
        while !thread.is_finished() && started.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "Shutdown waited {:?} for the queued connect",
            started.elapsed()
        );
        thread.join().expect("the network thread panicked");
    }

    #[tokio::test]
    async fn shutdown_ends_the_network_task() {
        let (net_tx, net_rx) = tokio_mpsc::channel(8);
        let task = spawn_network_task(
            net_rx,
            net_tx.clone(),
            Arc::new(Quiet::default()),
            node("shutdown-task"),
            String::new(),
            Arc::new(MemoryPeerStore::default()),
            None,
        );
        net_tx
            .send(NetCmd::Shutdown)
            .await
            .expect("the network loop is listening");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the network task outlived Shutdown")
            .expect("the network task panicked");
    }

    async fn session(
        handler: &Arc<Quiet>,
        net_tx: &tokio_mpsc::UnboundedSender<NetCmd>,
        store: &Arc<dyn PeerStore>,
    ) -> crate::rtc::WebRtcClient {
        crate::rtc::WebRtcClient::new(
            handler.clone(),
            net_tx.clone(),
            node("aa-me"),
            "zz-peer".to_string(),
            String::new(),
            None,
            store.clone(),
            p2p_node::lan::Link::Account,
        )
        .await
        .expect("a peer connection")
    }

    async fn uploading(peer: &crate::rtc::WebRtcClient) -> uuid::Uuid {
        let upload = uuid::Uuid::new_v4();
        peer.node_context
            .unconfirmed_uploads
            .lock()
            .await
            .insert(upload);
        upload
    }

    #[tokio::test]
    async fn shutdown_fails_the_uploads_its_sessions_left_unconfirmed() {
        let handler = Arc::new(Quiet::default());
        let (net_tx, _net_rx) = tokio_mpsc::unbounded_channel();
        let store: Arc<dyn PeerStore> = Arc::new(MemoryPeerStore::default());
        let peer = session(&handler, &net_tx, &store).await;
        let _ = peer.peer_connection.close().await;
        let upload = uploading(&peer).await;
        let mut manager =
            NetworkManager::new(node("aa-me"), String::new(), handler.clone(), net_tx, store);
        manager.active_peers.insert("zz-peer".to_string(), peer);

        manager.shutdown().await;

        assert_eq!(*handler.receipts.lock().unwrap(), [(upload, false)]);
    }

    #[tokio::test]
    async fn a_dropped_session_fails_its_unconfirmed_uploads_at_once() {
        let handler = Arc::new(Quiet::default());
        let (net_tx, _net_rx) = tokio_mpsc::unbounded_channel();
        let store: Arc<dyn PeerStore> = Arc::new(MemoryPeerStore::default());
        let peer = session(&handler, &net_tx, &store).await;
        let upload = uploading(&peer).await;
        let connection = peer.peer_connection.clone();
        let mut manager =
            NetworkManager::new(node("aa-me"), String::new(), handler.clone(), net_tx, store);
        manager.active_peers.insert("zz-peer".to_string(), peer);

        manager
            .handle_net_cmd(NetCmd::DisconnectPeer("zz-peer".to_string()))
            .await;
        assert_eq!(*handler.receipts.lock().unwrap(), [(upload, false)]);

        let deadline = Instant::now() + Duration::from_secs(5);
        while connection.connection_state()
            != webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Closed
        {
            assert!(Instant::now() < deadline, "the session was never closed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(*handler.receipts.lock().unwrap(), [(upload, false)]);
    }

    #[tokio::test]
    async fn an_upload_to_a_device_without_a_session_fails_at_once() {
        let handler = Arc::new(Quiet::default());
        let (net_tx, _net_rx) = tokio_mpsc::unbounded_channel();
        let store: Arc<dyn PeerStore> = Arc::new(MemoryPeerStore::default());
        let mut manager =
            NetworkManager::new(node("aa-me"), String::new(), handler.clone(), net_tx, store);
        let upload = uuid::Uuid::new_v4();

        for msg in [
            P2pMessage::FileUploadRequest {
                resource_id: "fs-theirs".to_string(),
                target_path: "/".to_string(),
                file_name: "a.txt".to_string(),
                total_size: 1,
                transfer_id: upload,
                permissions: None,
            },
            P2pMessage::FileChunk {
                transfer_id: upload,
                offset: 0,
                data: vec![1],
            },
        ] {
            manager
                .handle_net_cmd(NetCmd::SendToPeer("zz-gone".to_string(), msg))
                .await;
        }

        assert_eq!(*handler.receipts.lock().unwrap(), [(upload, false)]);
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_for_a_full_queue() {
        let handler = Arc::new(Quiet::default());
        let (net_tx, _net_rx) = tokio_mpsc::unbounded_channel();
        let store: Arc<dyn PeerStore> = Arc::new(MemoryPeerStore::default());
        let peer = crate::rtc::WebRtcClient::new(
            handler.clone(),
            net_tx.clone(),
            node("aa-me"),
            "zz-peer".to_string(),
            String::new(),
            None,
            store.clone(),
            p2p_node::lan::Link::Account,
        )
        .await
        .expect("a peer connection");
        let connection = peer.peer_connection.clone();
        let mut manager = NetworkManager::new(node("aa-me"), String::new(), handler, net_tx, store);
        manager.active_peers.insert("zz-peer".to_string(), peer);

        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), manager.shutdown())
            .await
            .expect("shutdown waited for the full queue");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(manager.active_peers.is_empty());
        assert_eq!(
            connection.connection_state(),
            webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Closed
        );
    }

    #[tokio::test]
    async fn a_sender_waits_while_the_loop_holds_a_full_queue() {
        let gate = Gate::shut();
        let (net_tx, task) = held_network(&gate, 4);
        net_tx
            .send(NetCmd::ApplyTurnCredentials(None))
            .await
            .expect("the network loop is listening");
        until("the command to start", || {
            gate.held.load(Ordering::SeqCst) == 1
        })
        .await;

        assert_eq!(fill(&net_tx).await, QUEUED + 4);
        let next = tokio::spawn({
            let net_tx = net_tx.clone();
            async move { net_tx.send(chunk()).await.is_ok() }
        });
        let shutdown = tokio::spawn({
            let net_tx = net_tx.clone();
            async move { net_tx.send(NetCmd::Shutdown).await.is_ok() }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!next.is_finished(), "a sender got past a full queue");

        gate.open.add_permits(1);
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the network task outlived Shutdown")
            .expect("the network task panicked");
        assert!(next.await.expect("the sender panicked"));
        assert!(shutdown.await.expect("the sender panicked"));
    }

    #[tokio::test]
    async fn commands_the_loop_sends_itself_do_not_wait_for_a_full_queue() {
        let gate = Gate::shut();
        let (net_tx, task) = held_network(&gate, 4);
        let mut callers = Vec::new();
        for i in 0..3 {
            let caller = webrtc::api::APIBuilder::new()
                .build()
                .new_peer_connection(
                    webrtc::peer_connection::configuration::RTCConfiguration::default(),
                )
                .await
                .expect("a peer connection");
            caller
                .create_data_channel("data", None)
                .await
                .expect("a data channel");
            let offer = caller.create_offer(None).await.expect("an offer");
            let inbound = nodeinnet_p2p::rtc::InboundRtcSignal {
                from_node_id: format!("zz-{i}"),
                signal: RtcSignal::Offer {
                    sdp: offer.sdp,
                    ice_restart: false,
                },
            };
            net_tx
                .send(NetCmd::HandleInboundSignal(
                    inbound,
                    p2p_node::lan::Link::Account,
                ))
                .await
                .expect("the network loop is listening");
            callers.push(caller);
        }
        net_tx
            .send(NetCmd::ApplyTurnCredentials(None))
            .await
            .expect("the network loop is listening");
        until("the redial to start", || {
            gate.held.load(Ordering::SeqCst) == 1
        })
        .await;
        assert!(
            gate.redials.lock().unwrap()[0].contains("redialling 3 peer(s)"),
            "{:?}",
            gate.redials.lock().unwrap()
        );

        fill(&net_tx).await;
        gate.open.add_permits(1);
        until("the three sessions to drop", || {
            gate.dropped.load(Ordering::SeqCst) == 3
        })
        .await;

        net_tx
            .send(NetCmd::Shutdown)
            .await
            .expect("the network loop is listening");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the network task outlived Shutdown")
            .expect("the network task panicked");
        for caller in callers {
            let _ = caller.close().await;
        }
    }

    #[tokio::test]
    async fn shutdown_overtakes_a_held_command_and_the_queue_behind_it() {
        let gate = Gate::shut();
        let (net_tx, task) = held_network(&gate, 4);
        net_tx
            .send(NetCmd::ApplyTurnCredentials(None))
            .await
            .expect("the network loop is listening");
        until("the command to start", || {
            gate.held.load(Ordering::SeqCst) == 1
        })
        .await;
        for _ in 0..3 {
            net_tx
                .send(chunk())
                .await
                .expect("the network loop is listening");
        }
        net_tx
            .send(NetCmd::Shutdown)
            .await
            .expect("the network loop is listening");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("Shutdown waited for the held command")
            .expect("the network task panicked");
    }

    #[tokio::test]
    async fn a_lan_signal_does_not_wait_for_the_queue_to_drain() {
        let handler = Arc::new(Upload::default());
        let (net_tx, net_rx) = tokio_mpsc::channel(4);
        let (private_key, _) = nodeinnet_p2p::crypto::generate_ed25519_keypair();
        let task = spawn_network_task(
            net_rx,
            net_tx.clone(),
            handler.clone(),
            node("aa-me"),
            private_key,
            Arc::new(MemoryPeerStore::default()),
            Some(p2p_node::lan::LanConfig {
                name: "me".to_string(),
                os: "linux".to_string(),
                kind: "desktop".to_string(),
                visibility: p2p_node::lan::Visibility::Off,
                browse: false,
                port: 0,
                resources: Vec::new(),
                trust: Arc::new(NoTrust),
                test_mode: true,
            }),
        );
        until("the LAN to report its state", || {
            handler.lan_events.load(Ordering::SeqCst) > 0
        })
        .await;
        let seen = handler.lan_events.load(Ordering::SeqCst);

        let mut sent = 0;
        while handler.lan_events.load(Ordering::SeqCst) == seen {
            assert!(sent < 400, "a LAN signal waited behind {sent} chunks");
            if sent == 2 * QUEUED {
                net_tx
                    .send(NetCmd::Lan(crate::LanCmd::Browse(false)))
                    .await
                    .expect("the network loop is listening");
            }
            net_tx
                .send(NetCmd::SendP2p(String::new()))
                .await
                .expect("the network loop is listening");
            sent += 1;
        }
        let queued = sent - handler.chunks.load(Ordering::SeqCst);
        assert!(queued >= QUEUED, "only {queued} chunks were queued");

        net_tx
            .send(NetCmd::Shutdown)
            .await
            .expect("the network loop is listening");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the network task outlived Shutdown")
            .expect("the network task panicked");
    }

    #[tokio::test]
    async fn after_disconnect_two_ticks_dial_no_cached_peer() {
        let handler = Arc::new(Quiet::default());
        let (net_tx, mut net_rx) = tokio_mpsc::unbounded_channel();
        let store = Arc::new(Cache::default());
        store.update(&mut |peers| {
            peers.insert(
                "zz-cached".to_string(),
                PeerConfig {
                    name: "cached".to_string(),
                    public_key: String::new(),
                    os: "linux".to_string(),
                    last_known_addresses: vec!["127.0.0.1:9".to_string()],
                },
            );
        });
        let mut manager = NetworkManager::new(
            node("aa-me"),
            String::new(),
            handler.clone(),
            net_tx,
            store.clone(),
        );
        manager
            .last_known_nodes
            .insert("zz-cached".to_string(), node("zz-cached"));

        manager.handle_net_cmd(NetCmd::Disconnect).await;
        tokio::task::yield_now().await;
        for _ in 0..2 {
            manager.handle_tick().await;
            assert!(net_rx.try_recv().is_err(), "an offline tick asked to dial");
        }
        manager
            .handle_net_cmd(NetCmd::AutoConnect("zz-cached".to_string()))
            .await;
        manager
            .handle_net_cmd(NetCmd::Call("zz-cached".to_string()))
            .await;

        assert!(manager.active_peers.is_empty());
        assert_eq!(handler.dialled.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.reads.load(Ordering::SeqCst),
            0,
            "an offline manager went through the cached addresses"
        );
    }
}
