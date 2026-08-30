# p2p-common

The node.in.net peer-to-peer transport: the wire protocol two peers agree on,
the peer node, and the client that connects to it. The capabilities a node
serves live in [`p2p-functions`](https://github.com/node-in-net/p2p-functions);
nothing here reads files, opens terminals or captures screens.

## Crates

| Crate | What it is |
| --- | --- |
| `nodeinnet-p2p` | The vocabulary: the `P2pMessage` command set, the node and shared-resource model, WebRTC signalling types, crypto (ed25519 identity, handshake signing), and the BSON wire format. Pure data and (de)serialisation — no I/O, no transport, no async runtime. |
| `p2p-node` | The peer node: local mesh, mDNS discovery, Noise-encrypted sessions, and the access check that decides whether an incoming message may touch a shared resource. |
| `client-core` | The client: WebRTC transport, signalling-server WebSocket, peer orchestration, chunked file transfer, remote-desktop decoding, authentication. |

## Dependencies

The only dependency of ours is [`common`](https://github.com/node-in-net/common),
for its `common` and `client-config` crates. Nothing here depends on `ui-common`
or on `p2p-functions` — implementations depend on this repository, never the
other way round.

## Building

There is no workspace manifest at the root: the consuming project defines the
workspace, the same way `common` and `ui-common` are laid out. Build a crate
directly, or build from a project that includes this repository as a submodule.

`nodeinnet-p2p` is self-contained and builds and tests on its own:

```sh
cd nodeinnet-p2p && cargo test
```

The other two need the `common` repository checked out alongside, because the
consuming workspace resolves `common` and `client-config` for them.

## Serving capabilities

This repository transports messages; it does not implement what they ask for.
An application installs handlers from `p2p-functions` at startup, and chooses
which of them to serve:

```rust
p2p_handlers::install(Capabilities::FILESYSTEM | Capabilities::NETWORK);
```

A node that installs nothing still connects to peers and consumes everything
they share — it just offers nothing of its own.

## Contributing

Every commit needs a `Signed-off-by` line certifying the
[Developer Certificate of Origin](DCO); a CI check enforces it. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the build steps and what to run before
opening a pull request.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
