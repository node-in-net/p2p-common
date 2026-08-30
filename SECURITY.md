# Security Policy

## Reporting a vulnerability

Please report security issues privately, **not** through a public issue.

Use GitHub's private vulnerability reporting: open the repository's
**Security** tab and press **Report a vulnerability**, or go straight to
[the form](https://github.com/node-in-net/p2p-common/security/advisories/new).
The report is visible only to the maintainers, and the fix can be developed in
a private fork from the same place.

Include what you can — the affected crate and version, what an attacker gains,
and steps or a proof of concept. We aim to acknowledge within 72 hours and to
keep you informed while a fix is prepared. Please give us a reasonable window to
release before disclosing publicly.

## What is in scope

This repository carries the transport and its guarantees. Implementations —
filesystem sandboxing, proxying, terminals — live in `p2p-functions` and are in
scope of that repository.

| Area | Where |
| --- | --- |
| Node identity and handshake signing (ed25519) | `nodeinnet-p2p/src/crypto.rs` |
| Capability enforcement — per-resource session tokens, HMAC, and the access check on every incoming message | `nodeinnet-p2p`, `client-core`, `p2p-node` |
| Noise-encrypted local-mesh sessions | `p2p-node/src/local_mesh.rs` |
| WebRTC transport, chunk framing and reassembly | `client-core/src/rtc/` |

Findings we consider serious include: reaching a resource a node never shared,
forging or replaying a handshake, recovering a session token, and anything that
lets one peer act as another.

## What is out of scope

- Vulnerabilities in third-party crates — report those upstream, though we are
  glad to hear which of our dependencies is affected.
- Denial of service from a peer you have already authorised: a peer that
  completed the zero-trust handshake is trusted by design.
- Findings that require an attacker to already control the machine running the
  node.

## Supported versions

This repository is consumed as a submodule and has no release train yet.
Security fixes land on `main`; consuming projects update their submodule
pointer. Once versioned releases exist, this section will name the supported
ones.
