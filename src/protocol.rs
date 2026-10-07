// Portions adapted from Kilombino Kilowallet/Kilojoin (Apache-2.0).
// Modified for Paperclip; Paperclip modifications are MIT. See NOTICE and licenses/.
//! Kilojoin v1 transaction agreement. Relay data is never a signing authority.
use super::crypto::{self, Event};
use anyhow::{ensure, Context};
use bitcoin::{
	secp256k1::{ecdsa::Signature, Message, Secp256k1, SecretKey},
	Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, str::FromStr};

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Terms {
	pub v: u32,
	pub network: String,
	pub id: String,
	pub public_key: String,
	pub denomination: u64,
	pub fee_rate: f64,
	pub min_peers: usize,
	pub max_peers: usize,
	pub private: bool,
	pub timeout: u64,
	pub state: String,
	pub peers: usize,
}
impl Terms {
	pub fn validate(&self) -> anyhow::Result<()> {
		ensure!(
			self.v == 1 && self.network == "blake2b",
			"unsupported pool protocol or network"
		);
		ensure!(
			crypto::bytes(&self.id)?.len() == 8 && crypto::bytes(&self.public_key)?.len() == 32,
			"invalid pool identity"
		);
		ensure!(
			(10000..=100000000).contains(&self.denomination)
				&& self.fee_rate.is_finite()
				&& (1.0..=500.0).contains(&self.fee_rate),
			"pool amount or rate out of range"
		);
		ensure!(
			(2..=20).contains(&self.max_peers)
				&& (2..=self.max_peers).contains(&self.min_peers)
				&& self.peers <= self.max_peers,
			"invalid peer limits"
		);
		ensure!(
			["open", "closing", "done", "aborted"].contains(&self.state.as_str()),
			"invalid pool state"
		);
		Ok(())
	}
	pub fn event(e: &Event) -> anyhow::Result<Self> {
		e.verify()?;
		ensure!(
			e.kind == 32022 && e.tag("t") == Some("kilojoin"),
			"not a pool announcement"
		);
		let t: Self = serde_json::from_str(&e.content)?;
		t.validate()?;
		ensure!(
			e.pubkey == t.public_key && e.tag("d") == Some(t.id.as_str()),
			"pool identity mismatch"
		);
		Ok(t)
	}
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Coin {
	pub txid: String,
	pub vout: u32,
	pub value: u64,
	pub pubkey: String,
}
impl Coin {
	pub fn outpoint(&self) -> anyhow::Result<OutPoint> {
		Ok(OutPoint {
			txid: self.txid.parse()?,
			vout: self.vout,
		})
	}
	pub fn name(&self) -> String {
		format!("{}:{}", self.txid, self.vout)
	}
	pub fn key(&self) -> anyhow::Result<PublicKey> {
		let k = PublicKey::from_str(&self.pubkey)?;
		ensure!(k.compressed && self.pubkey.len() == 66, "compressed key required");
		Ok(k)
	}
	pub fn script(&self) -> anyhow::Result<ScriptBuf> {
		Ok(ScriptBuf::new_p2wpkh(&self.key()?.wpubkey_hash()?))
	}
	pub fn validate(&self) -> anyhow::Result<()> {
		ensure!(
			crypto::bytes(&self.txid)?.len() == 32 && self.value > 0 && self.value <= 2100000000000000,
			"invalid coin"
		);
		self.outpoint()?;
		self.key()?;
		Ok(())
	}
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Seat {
	pub token_hash: String,
	pub coin: Coin,
	pub change_script: String,
	pub change_value: u64,
}
pub fn fee(rate: f64, change: bool) -> u64 {
	(rate * if change { 135.25 } else { 104.25 }).ceil() as u64
}
pub fn change(value: u64, amount: u64, rate: f64) -> anyhow::Result<u64> {
	let excess = value.checked_sub(amount).context("coin too small")?;
	if excess > fee(rate, true) + 294 {
		Ok(excess - fee(rate, true))
	} else {
		ensure!(excess >= fee(rate, false), "coin too small");
		Ok(0)
	}
}
impl Seat {
	pub fn validate(&self, terms: &Terms) -> anyhow::Result<()> {
		self.coin.validate()?;
		ensure!(
			self.change_value == change(self.coin.value, terms.denomination, terms.fee_rate)?,
			"incorrect change"
		);
		if self.change_value == 0 {
			ensure!(self.change_script.is_empty(), "unexpected change script");
		} else {
			ensure!(
				ScriptBuf::from_bytes(crypto::bytes(&self.change_script)?).is_p2wpkh(),
				"v1 requires P2WPKH change"
			);
		}
		Ok(())
	}
}
pub fn ownership(pool: &str, join: &str, coin: &Coin) -> [u8; 32] {
	crypto::hash(format!(
		"kilojoin/v1/own|{pool}|{join}|{}|{}",
		coin.name(),
		coin.value
	))
}
pub fn change_hash(pool: &str, seat: &Seat) -> [u8; 32] {
	crypto::hash(format!(
		"kilojoin/v1/change|{pool}|{}|{}|{}",
		seat.coin.name(),
		seat.change_script,
		seat.change_value
	))
}
pub fn token_hash(token: &str) -> String {
	crypto::hex(&crypto::hash(format!("kilojoin/v1/token|{token}")))
}
pub fn proof(key: &SecretKey, hash: [u8; 32]) -> String {
	crypto::hex(
		&Secp256k1::new()
			.sign_ecdsa(&Message::from_digest(hash), key)
			.serialize_der(),
	)
}
pub fn verify_proof(coin: &Coin, hash: [u8; 32], signature: &str) -> anyhow::Result<()> {
	Secp256k1::new()
		.verify_ecdsa(
			&Message::from_digest(hash),
			&Signature::from_der(&crypto::bytes(signature)?)?,
			&coin.key()?.inner,
		)
		.context("invalid ownership/change proof")
}

#[derive(Clone)]
pub struct Plan {
	pub tx: Transaction,
	pub coins: Vec<Coin>,
	pub previous: Vec<TxOut>,
	pub fee: u64,
}
impl Plan {
	pub fn new(
		terms: &Terms,
		seats: &[Seat],
		outputs: &[String],
		mine: &Seat,
		mix: &str,
	) -> anyhow::Result<Self> {
		terms.validate()?;
		ensure!(
			(terms.min_peers..=terms.max_peers).contains(&seats.len()) && outputs.len() == seats.len(),
			"incomplete round"
		);
		ensure!(
			seats
				.iter()
				.filter(|s| s.coin == mine.coin
					&& s.change_script == mine.change_script
					&& s.change_value == mine.change_value)
				.count() == 1,
			"our seat was changed"
		);
		ensure!(
			outputs.iter().filter(|s| s.as_str() == mix).count() == 1,
			"our mixed output is missing"
		);
		let mut inputs = HashSet::new();
		let mut input_scripts = HashSet::new();
		for seat in seats {
			seat.validate(terms)?;
			ensure!(inputs.insert(seat.coin.name()), "duplicate coin");
			input_scripts.insert(seat.coin.script()?.to_hex_string());
		}
		let mut scripts = HashSet::new();
		let mut mixout = Vec::new();
		let mut changes = Vec::new();
		for script in outputs {
			let spk = ScriptBuf::from_bytes(crypto::bytes(script)?);
			ensure!(
				spk.is_p2wpkh() && scripts.insert(script.clone()) && !input_scripts.contains(script),
				"invalid or reused mixed output"
			);
			mixout.push(TxOut {
				value: Amount::from_sat(terms.denomination),
				script_pubkey: spk,
			});
		}
		for s in seats.iter().filter(|s| s.change_value > 0) {
			ensure!(
				scripts.insert(s.change_script.clone()) && !input_scripts.contains(&s.change_script),
				"reused change script"
			);
			changes.push(TxOut {
				value: Amount::from_sat(s.change_value),
				script_pubkey: ScriptBuf::from_bytes(crypto::bytes(&s.change_script)?),
			});
		}
		mixout.sort_by_key(|o| o.script_pubkey.to_hex_string());
		changes.sort_by_key(|o| o.script_pubkey.to_hex_string());
		mixout.extend(changes);
		let mut coins: Vec<_> = seats.iter().map(|s| s.coin.clone()).collect();
		coins.sort_by_key(|c| (c.txid.clone(), c.vout));
		let total: u64 = coins.iter().map(|c| c.value).sum();
		let spend: u64 = mixout.iter().map(|o| o.value.to_sat()).sum();
		let paid = total.checked_sub(spend).context("negative fee")?;
		let vb = 10.5 + 68.0 * coins.len() as f64 + 31.0 * mixout.len() as f64;
		ensure!(
			paid >= (terms.fee_rate * vb * 0.95).floor() as u64
				&& paid <= (fee(terms.fee_rate, true) + 295) * coins.len() as u64,
			"fee outside pool bounds"
		);
		let tx = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: bitcoin::absolute::LockTime::ZERO,
			input: coins
				.iter()
				.map(|c| {
					Ok(TxIn {
						previous_output: c.outpoint()?,
						script_sig: ScriptBuf::new(),
						sequence: Sequence(0xfffffffd),
						witness: Witness::new(),
					})
				})
				.collect::<anyhow::Result<_>>()?,
			output: mixout,
		};
		let previous = coins
			.iter()
			.map(|c| {
				Ok(TxOut {
					value: Amount::from_sat(c.value),
					script_pubkey: c.script()?,
				})
			})
			.collect::<anyhow::Result<_>>()?;
		Ok(Self {
			tx,
			coins,
			previous,
			fee: paid,
		})
	}
	pub fn digest(&self, i: usize) -> anyhow::Result<[u8; 32]> {
		crate::sighash::p2wpkh_all(&self.tx, &self.previous, i)
	}
	pub fn sign(&self, coin: &Coin, key: &SecretKey) -> anyhow::Result<String> {
		let i = self
			.coins
			.iter()
			.position(|c| c == coin)
			.context("missing our coin")?;
		ensure!(
			bitcoin::secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), key) == coin.key()?.inner,
			"coin key mismatch"
		);
		let mut sig = Secp256k1::new()
			.sign_ecdsa_low_r(&Message::from_digest(self.digest(i)?), key)
			.serialize_der()
			.to_vec();
		sig.push(0x21);
		Ok(crypto::hex(&sig))
	}
	pub fn verify(&self, name: &str, signature: &str) -> anyhow::Result<usize> {
		let i = self
			.coins
			.iter()
			.position(|c| c.name() == name)
			.context("unknown input")?;
		let data = crypto::bytes(signature)?;
		ensure!(
			data.len() >= 9 && data.last() == Some(&0x21),
			"unified SIGHASH_ALL required"
		);
		let sig = Signature::from_der(&data[..data.len() - 1])?;
		let mut low = sig;
		low.normalize_s();
		ensure!(sig == low, "high-S signature");
		Secp256k1::new().verify_ecdsa(
			&Message::from_digest(self.digest(i)?),
			&sig,
			&self.coins[i].key()?.inner,
		)?;
		Ok(i)
	}
}
