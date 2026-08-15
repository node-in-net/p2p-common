# Contributing to p2p-common

Thanks for taking the time to contribute.

This repository is the peer-to-peer transport behind
[node.in.net](https://node.in.net) — the protocol two peers agree on, the peer
node, and the client that connects to it. Implementations live in
`p2p-functions`. It is consumed as a submodule, so a change here reaches every
application that embeds it.

## Developer Certificate of Origin (sign-off required)

This project does **not** use a CLA. Instead, every commit must carry a
`Signed-off-by` line, certifying the [Developer Certificate of Origin](DCO)
(the full text is in the `DCO` file at the repository root).

Git adds the line for you:

```sh
git commit -s -m "your message"
```

It looks like this, and the name and e-mail must match the commit author:

```
Signed-off-by: Jane Doe <jane@example.com>
```

To never forget it, install a hook — once per clone. Note that
`git config format.signoff` does **not** do this; it only affects
`git format-patch`:

```sh
printf '%s\n' '#!/bin/sh' 'git interpret-trailers --in-place --if-exists doNothing --trailer "Signed-off-by: $(git config user.name) <$(git config user.email)>" "$1"' > .git/hooks/prepare-commit-msg
chmod +x .git/hooks/prepare-commit-msg
```

It reads `user.name` and `user.email` from git's config, runs for `git commit`
from any editor or GUI, and does not add a second line when you already
passed `-s`.

Missing a sign-off on an existing commit? `git commit --amend -s` fixes the
last one; `git rebase --signoff <base>` fixes a whole branch. A CI check
enforces this on every pull request.

## Licensing of contributions

Unless you state otherwise, any contribution you submit is licensed under the
same terms as the project — **MIT OR Apache-2.0**, at the user's option. See
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

The name "node.in.net" and the project logo are not covered by the code
license.

## Getting the source

This repository has no workspace manifest of its own: the consuming project
defines the workspace. Clone it directly to work on it, or work inside a
project that already includes it as a submodule.

```sh
git clone https://github.com/node-in-net/p2p-common.git
```

Two of the three crates resolve `common` and `client-config` from the
[`common`](https://github.com/node-in-net/common) repository, so they only
build from a workspace that provides both.

## Building

Rust (stable) is required. `nodeinnet-p2p` is self-contained and builds and tests on
its own:

```sh
cd nodeinnet-p2p && cargo test
```

For the rest, build from the consuming workspace and name the packages:

```sh
cargo check -p nodeinnet-p2p -p client-core -p p2p-node
```

Nothing here talks to the operating system, so a build needs no platform
libraries — no GTK, GStreamer or capture SDKs.

## A note on the protocol crate

`nodeinnet-p2p` is the vocabulary two peers share. Changing a `P2pMessage`
variant, a field, or a `ResourceType` changes the wire format, and peers running
older builds will no longer understand it. Prefer additive changes: new fields
carry `#[serde(default)]`, new variants leave existing ones alone. If a breaking
change is unavoidable, say so explicitly in the pull request.

Capabilities are not implemented here. `p2p-node` checks that an incoming
message targets a resource this node actually shares, then hands it to the
handler an application installed; with no handler installed, the node serves
nothing and still consumes everything its peers share.

## Before you open a pull request

- Keep changes focused and prefer reusing existing abstractions over adding new
  ones.
- Comments in English, and only where the code cannot speak for itself.
- Run, from the consuming workspace:

```sh
cargo fmt --check -p nodeinnet-p2p -p client-core -p p2p-node
cargo clippy --all-targets -- -D warnings
cargo test
```

The real-transport tests in `client-core` need loopback UDP and are `#[ignore]`d
by default. Run them serially — parallel runs saturate loopback ICE and flake:

```sh
cargo test -p client-core -- --ignored --test-threads=1 loopback
```

## Reporting bugs

A good report includes the platform, the crate and version, and — most valuable
— concrete steps to reproduce. For connection problems, the node's own log is
the fastest evidence: every peer session logs its handshake, ICE state changes
and dropped packets through `on_log`, including why a message was refused.
