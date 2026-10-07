# Paperclip Kilojoin Rust

**Experimental. Not independently audited.** A Rust implementation of Kilojoin v1
for the **XBT BLAKE2b chain**, interoperable at the production-vector level with
Kilombino's Kotlin implementation. This is not a Bitcoin SHA-256 Coinjoin client.
No live funded cross-client round has been validated with this port yet.

The library provides:

- Pool terms, ownership/change proofs, private-pool password proofs, and canonical transaction construction.
- Unified `SIGHASH_ALL` (`0x21`) for v1 P2WPKH inputs, deterministic ECDSA, and verification of participant signatures.
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

- [Kilojoin protocol and vectors](https://github.com/Kilombino/kilojoin/tree/45a6ddb9477c92c5f31afb6017d48ebf249e155b/docs)
- [Kilowallet reference](https://github.com/Kilombino/kilowallet/tree/102ff2f4f7a8097d81e79eb1b87e42ff413c119e/app/src/main/java/com/kilombino/pyblockwatch/coinjoin)
- Default relay for hosts: `wss://relay.kilombino.com`; this library does not contact it.
- XBT mainnet pool name: `blake2b`; denomination 10,000–100,000,000 sats; 2–20 participants.
- P2WPKH inputs, mixed outputs, and change. No Taproot, multisig, or hardware ownership-proof exchange.
- Production vectors verify both unified sighashes, exact transaction signatures, raw transaction,
  txid, ownership/change proofs, password proof, and the encrypted channel event.

Some validation is deliberately stricter than the reference: bounded input sizes,
valid compressed keys, exact local seat preservation, P2WPKH change, strict DER/low-S
transaction signatures, and no unlocking merely because a signed round times out.
Public APIs may change before a stable release.

## Privacy and limitations

Inputs and change are visible to participants. All participants share the pool key,
so they can forge control messages or disrupt a round. Equal outputs are not a guarantee
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

Apache-2.0. The protocol/state-machine port and fixtures derive from Kilombino's
Apache-2.0 projects. See [NOTICE](NOTICE) and [LICENSE](LICENSE).
