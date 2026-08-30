# nodeinnet-p2p

The wire protocol of the [node.in.net](https://node.in.net) peer-to-peer stack,
part of [`p2p-common`](../README.md).

Everything two peers must agree on, and nothing else: the `P2pMessage` command
set, the node and shared-resource model, WebRTC signalling types, ed25519
identity and handshake signing, and the BSON wire format.

Pure data and (de)serialisation — no I/O, no transport, no async runtime. It is
the only crate here that builds and tests on its own:

```sh
cargo test
```

## License

[Apache License 2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT), at your option.
