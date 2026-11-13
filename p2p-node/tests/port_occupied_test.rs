use nodeinnet_p2p::crypto::generate_ed25519_keypair;
use p2p_node::lan::{Lan, LanConfig, TrustStore, Visibility};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Memory(Mutex<Option<String>>);

impl TrustStore for Memory {
    fn load(&self) -> std::io::Result<Option<String>> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save(&self, doc: &str) -> std::io::Result<()> {
        *self.0.lock().unwrap() = Some(doc.to_string());
        Ok(())
    }
}

#[tokio::test]
async fn the_next_port_is_taken_when_8308_is_busy() {
    let _held = std::net::TcpListener::bind("0.0.0.0:8308")
        .or_else(|_| std::net::TcpListener::bind("127.0.0.1:8308"));
    let (signals, _heard) = tokio::sync::mpsc::channel(64);
    let config = LanConfig {
        name: "port test".to_string(),
        os: "linux".to_string(),
        kind: "test".to_string(),
        visibility: Visibility::Open,
        browse: false,
        port: 8308,
        resources: vec![],
        trust: Arc::new(Memory::default()),
        test_mode: true,
    };
    let lan = Lan::start(config, &generate_ed25519_keypair().0, signals)
        .await
        .expect("lan");
    assert_eq!(lan.port(), Some(8309));
    lan.stop().await;
}
