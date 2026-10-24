//! Experimental Kilojoin v1–v4 interoperability for the XBT BLAKE2b chain.
//!
//! This library does not connect to a relay, access a wallet, persist state, or broadcast.
//! Integrators must validate UTXOs, authorize signing, atomically save the full [`round::Round`]
//! before sending its outbox, and retain reservations after a signature is released.
//! See the repository integration guide and limitations before using real coins.
pub mod blind;
pub mod crypto;
pub mod protocol;
pub mod round;
mod sighash;
#[cfg(test)]
mod tests;
