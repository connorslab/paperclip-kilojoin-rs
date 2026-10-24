# Paperclip Kilojoin Rust

**Experimental. Not independently audited.** A Rust implementation of Kilojoin v1–v4
for the **XBT BLAKE2b chain**, interoperable at the production-vector level with
Kilombino's Kotlin implementation. This is not a Bitcoin SHA-256 Coinjoin client.
No live funded cross-client round has been validated with this port yet.

The library provides:

- Pool terms, ownership/change proofs, private-pool password proofs, and canonical transaction construction.
- Unified `SIGHASH_ALL` (`0x21`) for P2WPKH and BIP86 Taproot inputs, deterministic ECDSA, and verification of participant signatures.
- NIP-01 Schnorr-signed events and NIP-44 v2 encrypted messages.
- A serializable round state machine and durable-outbox model, with separate output-publication routing hints.
- Production vectors and tests for replay, restart, voting, signature release, and timeout reservations.

It does **not** provide a wallet, chain backend, WebSocket client, Tor client,
background service, database, or automatic key management. Hosts own those boundaries.
No funds move merely by using the crate or running its tests.

## Build and test

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo doc --locked --no-deps
```

The repository is the distribution source for now; this crate has not been published
to crates.io. Pin an immutable Git commit in applications:

```toml
[dependencies]
paperclip-kilojoin = { git = "https://github.com/connorslab/paperclip-kilojoin-rs", rev = "<reviewed-commit>" }
```

See [INTEGRATION.md](INTEGRATION.md) for host responsibilities and the round lifecycle.
The Paperclip iOS wallet is one host implementation:
[paperclip-wallet-app](https://github.com/connorslab/paperclip-wallet-app/tree/feature/ios-wallet).

## Compatibility target

- [Kilojoin protocol and vectors](https://github.com/Kilombino/kilojoin/tree/b596f30c35d299d919f2a441493880711fc4c344/docs)
- [Kilowallet reference](https://github.com/Kilombino/kilowallet/tree/9165628aa872f13de3ffe2ef8422a7795dbc2dde/app/src/main/java/com/kilombino/pyblockwatch/coinjoin)
- Default relay for hosts: `wss://relay.kilombino.com`; this library does not contact it.
- XBT mainnet pool name: `blake2b`; denomination 10,000–100,000,000 sats; 2–20 participants.
- Homogeneous native SegWit or Taproot pools, up to 10 inputs per seat and 1–5 equal mixed outputs. No multisig or hardware ownership-proof exchange.
- Production vectors verify both unified sighashes, exact transaction signatures, raw transaction,
  txid, ownership/change proofs, password proof, and the encrypted channel event.

Some validation is deliberately stricter than the reference: bounded input sizes,
valid compressed keys, exact local seat preservation, P2WPKH change, strict DER/low-S
transaction signatures, and no unlocking merely because a signed round times out.
Public APIs may change before a stable release.

## Privacy and limitations

Inputs and change are visible to participants. Legacy v1/v2 participants share the pool key and can forge control messages.
V3/v4 authenticate creator control, keep seat tokens off-channel with MACs,
and register RFC 9474 blinded outputs from fresh keys. Members can still disrupt rounds. Equal outputs are not a guarantee
of anonymity. One UTXO per seat does not stop one person from controlling several seats.
The relay can correlate connections, IPs, and timing. A separate WebSocket and isolated
Tor circuit for output publication reduce exposure; they do not prove unlinkability.

Hosts must never silently reuse a signed input after abort or timeout. Another participant
may still broadcast the approved transaction. Persist reservations and reconcile the
actual chain outcome. Peer `tx` messages alone do not establish broadcast or confirmation.

Hardware wallets need custom-hash ownership/change proofs in addition to `0x21`
transaction signing. Some BLAKE2b Krux/SeedSigner forks implement the transaction
sighash, but this library does not supply the missing proof-signing exchange.

Ark is not part of Kilojoin v1. A host can later board the mixed output **alone** in a
separate transaction. A direct Ark output would require a protocol change and coordination
of recovery persistence before broadcast. This library implements neither Ark operation.

## License and attribution

Paperclip's original code and modifications are released under the **MIT License**.
See [LICENSE](LICENSE).

The adapted Kilombino portions in `src/crypto.rs`, `src/protocol.rs`, `src/round.rs`
and the upstream production fixture remain subject to Apache-2.0. Their license
and notices are retained in [licenses/Apache-2.0.txt](licenses/Apache-2.0.txt) and
[NOTICE](NOTICE). This is not an MIT-only relicensing of upstream code. The package's
SPDX expression is `MIT AND Apache-2.0`, reflecting both sets of obligations; it is
not a choice between licenses.

## v4 integration

New one-output pools use v3; two to five outputs use v4, matching upstream.
Each output is the denomination, so the mixed total is denomination × outputs.
Multiple inputs can consolidate UTXOs; multiple outputs instead create separately spendable coins.
The host must use `verification_coins` before `handle` and verify every returned coin's
value, unspent status, and script derived using the pool type. Passing `true` without
those checks bypasses the roster trust boundary. Repeat chain checks before signing.

Round serialization preserves old v1 state with defaults. Keep every selected input
reserved after any signature release. Persist blind requests, output identities and
the outbox before sending; retransmit the same events after reconnect. Subscribe to
the creator key as a recipient when hosting v3/v4, and use a separate relay connection
(and isolated Tor credentials) for each output event marked `isolated`.

Tests cover upstream v4 fee/MAC/transaction vectors, the RFC 9474 vector used by
Kilowallet, legacy-state loading, and local multi-input/multi-output round simulations.
These are not a funded live cross-client deployment test.
