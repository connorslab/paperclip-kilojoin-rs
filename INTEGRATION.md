# Host integration contract

## Host-owned boundaries

Use the same relay for all participants in a pool. Verify Nostr events before displaying
pool announcements (`Terms::event`). Apply wall-clock expiry and filter open/non-full pools.
Do not trust the relay's peer counts as proof of independent people or privacy.

Keep secrets and full `Round` state in protected storage. Its serialized fields include
ephemeral pool/join private keys and seat tokens. Never log or publish this serialization.
Do not store a wallet seed or coin private key in `Round`.

Obtain a fresh P2WPKH mixed address and a separate fresh P2WPKH change address. Persist
both derivation indices before announcing either. Keep mixed outputs and change labelled
separately; unknown restored history is not evidence of an unmixed coin.

## Constructing a round

`Round::new(RoundConfig, &coin_key, now)` validates the chosen terms and addresses,
binds the coin key, and prepares proofs. The host supplies a selected coin, fresh
addresses, connection policy, and a private-pool password when needed. No stable
high-level wallet interface is promised in this initial release.

- Generate a fresh join key with `crypto::secret()` and, for creators, a fresh pool key.
- The constructor computes change with `protocol::change` and validates the seat.
- The constructor signs `protocol::ownership` and `protocol::change_hash` with the input key.
- A creator uses the pool public key in its ownership proof; a joiner uses its join public key.
- Private pools use the spec's pool-id/password hash and HMAC proof; do not publish the password.
- Start with phase `joining`, empty channel state/outbox, and `signed = false`.
- Call `Round::start(now)`, then **atomically persist state and input reservation before publishing**.

One live round per selected input is mandatory. Reserve outside this library's state too
if your wallet has other payment/coin-selection paths.

## Receiving and sending

1. Subscribe to kind 2023 for both join and pool public keys, without a `since` cutoff.
2. Replay retained history in chronological order. Replay the channel again after welcome;
   messages received before the shared key was known could not be decrypted.
3. `Round::decode` verifies/decrypts the event for inspection. For a creator's incoming join,
   validate the input against an authoritative chain backend, including mempool spends,
   exact amount, and script. Pass the resulting `unspent` fact to `Round::handle`.
   `handle` verifies/decrypts again and applies atomically in memory: an error leaves state unchanged.
4. Persist after each accepted mutation. Do not rely on memory surviving suspension.
5. Publish the exact saved events from `outbox`. A rejected write is not success.
   Remove an event only after a positive relay acknowledgement, then persist.
6. Apply your own acknowledged channel events as well as peer echoes. Replay is idempotent.
   Acknowledgement does not establish a blockchain transaction's success.
7. Route `Outgoing::isolated` events through a separate connection. With Tor, use distinct
   SOCKS-auth isolation credentials/circuits. Do not silently fall back to direct networking.
8. Call `tick(now)` regularly while active; persist before emitting newly queued events.
   Reconnect with backoff, replay subscriptions, and retry the same saved events.

Bound relay messages, subscriptions, queued replay bytes, and connection timeouts in the
transport. The core bounds individual events and round history, but cannot protect an
unbounded transport queue. Debounce retries to avoid exhausting relay write limits.

## Signing and broadcast

Call `Round::plan()` and display the input, equal output, change, fee, and transaction ID.
After user approval, reconstruct the plan and require its transaction ID still matches
the reviewed plan. Query **every input** against the chain backend again; amounts and
scripts in relay messages are not chain evidence. Reject any unknown or spent input.

Derive only your selected input's private key, call `Plan::sign`, then
`Round::signed_message`. **Persist this state, its signed flag, reservation, and outbox
before sending the signature.** Never sign a replacement plan for that reservation.
Use `Plan::verify` for every participant signature before assembling witnesses. All must
end in `0x21`. Persist the complete transaction before attempting chain broadcast.

A timeout or `abort` after signing moves the round to `uncertain`, and `locked()` stays true.
Keep polling/reconciling. Mark confirmed only after querying the actual expected txid.
Release a conflicted reservation only after proving a different confirmed spend of its
input. A mempool conflict or a peer's `tx` claim is insufficient. Reorg policy belongs to
the host, which must continue checking selected inputs before any later signature.

`Round` does not broadcast or poll confirmations. The host sets terminal outcomes only
from chain evidence and persists them. Keep original signed plans for recovery and audit.

## Testing your host

The fixtures use public deterministic test keys; **never fund them**. Existing tests cover
crypto/transaction agreement and an in-memory two-peer lifecycle, not your wallet, relay,
Tor, persistence durability, or platform suspension. Test those boundaries separately.
No live funded cross-client round is claimed for this port.
