macro_rules! println {
    ($($arg:tt)*) => {};
}

use crate::local_mesh;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use nodeinnet_p2p::{crypto, NodeInfo};
use std::collections::HashMap;
use std::sync::OnceLock;

pub static MDNS_DAEMON: OnceLock<ServiceDaemon> = OnceLock::new();

pub fn get_mdns_daemon() -> &'static ServiceDaemon {
    MDNS_DAEMON.get_or_init(|| ServiceDaemon::new().unwrap())
}

// Start advertising this node on local network via mDNS
pub fn start_mdns_advertiser(
    node_id: &str,
    public_key: &str,
    private_key_b64: &str,
    port: u16,
    device_name: &str,
    device_os: &str,
) -> Result<(), String> {
    let mdns = get_mdns_daemon();
    let service_type = "_nodeinnet._tcp.local.";
    let instance_name = format!("{}.{}", node_id, service_type);

    let message = format!("{}:{}", node_id, port);
    let signature = crypto::sign_message(private_key_b64, message.as_bytes())?;

    let mut properties = HashMap::new();
    properties.insert("node_id".to_string(), node_id.to_string());
    properties.insert("port".to_string(), port.to_string());
    properties.insert("signature".to_string(), signature);
    properties.insert("public_key".to_string(), public_key.to_string());
    properties.insert("name".to_string(), device_name.to_string());
    properties.insert("os".to_string(), device_os.to_string());

    let service_info = ServiceInfo::new(
        service_type,
        &instance_name,
        &format!("{}.local.", node_id),
        "0.0.0.0", // Auto-detect interfaces
        port,
        Some(properties),
    )
    .map_err(|e| e.to_string())?
    .enable_addr_auto();

    println!(
        "[mDNS Advertiser] Registering service on local network: ID={}, Port={}",
        node_id, port
    );
    mdns.register(service_info).map_err(|e| e.to_string())?;
    Ok(())
}

// Start scanning for other local peers on subnet
pub fn start_mdns_scanner(
    my_id: String,
    private_key_b64: String,
    config: client_config::AppConfig,
) -> Result<(), String> {
    let mdns = get_mdns_daemon();
    let service_type = "_nodeinnet._tcp.local.";
    println!(
        "[mDNS Scanner] Starting browse query for service: {}",
        service_type
    );
    let receiver = mdns.browse(service_type).map_err(|e| e.to_string())?;

    tokio::spawn(async move {
        while let Ok(event) = receiver.recv_async().await {
            println!("[mDNS Scanner] Received ServiceEvent: {:?}", event);
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let peer_id = info.get_property_val_str("node_id");
                    let port_str = info.get_property_val_str("port");
                    let sig = info.get_property_val_str("signature");
                    let pub_key = info.get_property_val_str("public_key");
                    let name_prop = info.get_property_val_str("name");
                    let os_prop = info.get_property_val_str("os");

                    if let (Some(peer_id), Some(port_str), Some(sig), Some(pub_key)) =
                        (peer_id, port_str, sig, pub_key)
                    {
                        if peer_id == &my_id {
                            continue;
                        }

                        if let Ok(port) = port_str.parse::<u16>() {
                            let message = format!("{}:{}", peer_id, port);
                            if crypto::verify_message(sig, pub_key, message.as_bytes()).is_ok() {
                                // Update/register public key
                                let node_info = NodeInfo {
                                    id: peer_id.to_string(),
                                    name: name_prop
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| peer_id.to_string()),
                                    os: os_prop
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| "unknown".to_string()),
                                    version: "0.1.0".to_string(),
                                    app_type: "desktop".to_string(),
                                    build_type: "debug".to_string(),
                                    public_key: pub_key.to_string(),
                                    resources: vec![],
                                    is_online: true,
                                    last_used: 0,
                                    is_temporary: false,
                                };
                                nodeinnet_p2p::update_known_public_keys(&[node_info.clone()]);
                                config.update(
                                    "peers",
                                    |map: &mut HashMap<String, nodeinnet_p2p::PeerConfig>| {
                                        let entry = map.entry(peer_id.to_string()).or_default();
                                        entry.public_key = pub_key.to_string();
                                        entry.name = node_info.name.clone();
                                        entry.os = node_info.os.clone();
                                    },
                                );

                                if let Some(tx) = local_mesh::SIGNAL_TX.get() {
                                    let _ = tx
                                        .send(local_mesh::LocalMeshSignal::PeerDiscovered(
                                            node_info.clone(),
                                        ))
                                        .await;
                                }

                                // Cache all resolved IP addresses
                                let ips = info.get_addresses();
                                for ip in ips {
                                    let addr = format!("{}:{}", ip, port);

                                    config.update(
                                        "peers",
                                        |map: &mut HashMap<String, nodeinnet_p2p::PeerConfig>| {
                                            let entry = map.entry(peer_id.to_string()).or_default();
                                            if !entry.last_known_addresses.contains(&addr) {
                                                entry.last_known_addresses.push(addr.clone());
                                            }
                                        },
                                    );

                                    // Check if we are already connected to this peer, if not, attempt connection
                                    let connected = {
                                        let tunnels = local_mesh::get_active_tunnels().lock().await;
                                        tunnels.contains_key(peer_id)
                                    };

                                    if !connected {
                                        let peer_id_clone = peer_id.to_string();
                                        let addr_clone = addr.clone();
                                        let my_id_clone = my_id.clone();
                                        let private_key_b64_clone = private_key_b64.clone();
                                        let config_clone = config.clone();

                                        tokio::spawn(async move {
                                            let _ = local_mesh::connect_to_peer_signaling(
                                                addr_clone,
                                                peer_id_clone,
                                                my_id_clone,
                                                private_key_b64_clone,
                                                config_clone,
                                            )
                                            .await;
                                        });
                                    }
                                }
                                config.save();
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });

    Ok(())
}

pub fn stop_mdns_advertiser(node_id: &str) -> Result<(), String> {
    let mdns = get_mdns_daemon();
    let service_type = "_nodeinnet._tcp.local.";
    let instance_name = format!("{}.{}", node_id, service_type);
    let _ = mdns.unregister(&instance_name).map_err(|e| e.to_string())?;
    println!(
        "[mDNS Advertiser] Unregistered service for local network: ID={}",
        node_id
    );
    Ok(())
}

pub fn stop_mdns_scanner() -> Result<(), String> {
    let mdns = get_mdns_daemon();
    let service_type = "_nodeinnet._tcp.local.";
    let _ = mdns.stop_browse(service_type).map_err(|e| e.to_string())?;
    println!(
        "[mDNS Scanner] Stopped browse query for service: {}",
        service_type
    );
    Ok(())
}
