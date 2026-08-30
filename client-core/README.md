# client-core

The client side of the [node.in.net](https://node.in.net) stack, part of
[`p2p-common`](../README.md).

Connects to peers and drives the session: WebRTC transport, the signalling-server
WebSocket, peer orchestration and reconnection, the chunked framing that carries
BSON messages over a DataChannel, remote-desktop media decoding, and account
authentication over HTTP.

Headless and UI-free, so console, desktop, mobile and test binaries share one
implementation.

## License

[Apache License 2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT), at your option.
