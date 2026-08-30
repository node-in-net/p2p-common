use nodeinnet_p2p::{NodeInfo, P2pMessage};
use p2p_node::{MessageHandler, NodeContext};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

struct StubHandler {
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl MessageHandler for StubHandler {
    async fn handle(&self, msg: P2pMessage, ctx: NodeContext) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let P2pMessage::RequestSystemInfo { resource_id } = msg {
            ctx.send_msg(P2pMessage::SystemInfoResponse {
                resource_id,
                info: stub_sys_info(),
            })
            .await;
        }
    }
}

fn stub_sys_info() -> nodeinnet_p2p::p2p::SysInfo {
    nodeinnet_p2p::p2p::SysInfo {
        hostname: "test-host".to_string(),
        os_family: "unix".to_string(),
        os_type: "linux".to_string(),
        os_version: "0".to_string(),
        cpu_arch: "x86_64".to_string(),
        cpu_cores: 4,
        cpu_usage: 0.0,
        total_memory: 0,
        used_memory: 0,
        total_swap: 0,
        used_swap: 0,
        uptime: 0,
        network_interfaces: Vec::new(),
    }
}

fn build_mock_context() -> (NodeContext, Uuid, Uuid, Uuid) {
    let sys_id = Uuid::new_v4();
    let fs_id = Uuid::new_v4();
    let term_id = Uuid::new_v4();

    let info = NodeInfo {
        id: "test_node_id".to_string(),
        name: "test".to_string(),
        os: "linux".to_string(),
        version: "0.1.0".to_string(),
        app_type: "test".to_string(),
        build_type: "test".to_string(),
        resources: vec![
            nodeinnet_p2p::SharedResource {
                id: sys_id.to_string(),
                name: "system".to_string(),
                resource_type: nodeinnet_p2p::p2p::ResourceType::SystemInfo,
                config: None,
                is_active: true,
                session_token: Some("sys_token".to_string()),
            },
            nodeinnet_p2p::SharedResource {
                id: fs_id.to_string(),
                name: "fs".to_string(),
                resource_type: nodeinnet_p2p::p2p::ResourceType::Filesystem,
                config: None,
                is_active: true,
                session_token: Some("fs_token".to_string()),
            },
            nodeinnet_p2p::SharedResource {
                id: term_id.to_string(),
                name: "term".to_string(),
                resource_type: nodeinnet_p2p::p2p::ResourceType::Terminal,
                config: None,
                is_active: true,
                session_token: Some("term_token".to_string()),
            },
        ],
        public_key: String::new(),
        is_online: true,
        last_used: 0,
        is_temporary: false,
    };

    let (out_tx, _) = mpsc::channel(100);
    let (log_tx, _) = mpsc::channel(100);
    let (event_tx, _) = mpsc::channel(100);
    let peer_store = std::sync::Arc::new(nodeinnet_p2p::MemoryPeerStore::default());

    let ctx = NodeContext::new(
        out_tx,
        log_tx,
        event_tx,
        info,
        "the-asking-peer".to_string(),
        peer_store,
    );
    assert_eq!(
        ctx.peer_id, "the-asking-peer",
        "the context names the connection's peer, not anything self-declared on the wire"
    );
    ctx.is_authenticated.store(true, Ordering::Relaxed);

    (ctx, sys_id, fs_id, term_id)
}

#[tokio::test]
async fn request_is_routed_to_the_installed_handler() {
    let (ctx, sys_id, _, _) = build_mock_context();
    let (out_tx, mut out_rx) = mpsc::channel(100);
    let mut ctx2 = ctx.clone();
    ctx2.outgoing_tx = out_tx;

    ctx2.session_keys
        .lock()
        .await
        .insert(sys_id.to_string(), "sys_token".to_string());

    let calls = Arc::new(AtomicUsize::new(0));
    let _ = p2p_node::install_message_handler(Arc::new(StubHandler {
        calls: calls.clone(),
    }));

    ctx2.process_message(P2pMessage::RequestSystemInfo {
        resource_id: sys_id.to_string(),
    })
    .await;

    match tokio::time::timeout(Duration::from_secs(2), out_rx.recv()).await {
        Ok(Some(nodeinnet_p2p::OutboundP2pPayload::Message(env))) => match env.message {
            P2pMessage::SystemInfoResponse { resource_id, .. } => {
                assert_eq!(
                    resource_id,
                    sys_id.to_string(),
                    "response lost the resource id"
                );
            }
            other => panic!("expected SystemInfoResponse, got {other:?}"),
        },
        _ => panic!("the request never reached the handler"),
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "handler should run exactly once"
    );
}
