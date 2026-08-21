use std::net::TcpListener;

#[tokio::test]
async fn test_port_occupied_error() {
    let _listener =
        TcpListener::bind("127.0.0.1:8308").or_else(|_| TcpListener::bind("0.0.0.0:8308"));

    let my_id = "test_node_id".to_string();
    let dummy_priv_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();

    let config = client_config::AppConfig::new("p2p-node-port-test");
    let result =
        p2p_node::local_mesh::start_tcp_signaling_server(my_id, dummy_priv_key, config).await;

    assert!(
        result.is_err(),
        "Expected start_tcp_signaling_server to fail when port 8308 is occupied"
    );
    let err_msg = result.unwrap_err();
    println!("Captured expected bind error: {}", err_msg);
    assert!(
        err_msg.contains("failed to bind to port 8308")
            || err_msg.contains("failed to listen on port 8308")
    );
}
