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
	#[serde(default = "segwit")]
	pub script: String,
	#[serde(default = "one")]
	pub max_inputs: usize,
	#[serde(default = "one")]
	pub outputs: usize,
	#[serde(default)]
	pub creator: String,
	#[serde(default)]
	pub blind_key: String,
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
fn segwit() -> String {
	"p2wpkh".into()
}
fn one() -> usize {
	1
}
impl Terms {
	pub fn mix_total(&self) -> u64 {
		self.denomination * self.outputs as u64
	}
	pub fn accepts_script(&self, s: &ScriptBuf) -> bool {
		if self.script == "p2tr" {
			s.is_p2tr()
		} else {
			s.is_p2wpkh()
		}
	}
	pub fn fee(&self, change: bool, inputs: usize) -> u64 {
		let (i, o) = if self.script == "p2tr" {
			(57.75, 43.0)
		} else {
			(68.0, 31.0)
		};
		(self.fee_rate
			* (i * inputs as f64 + o * (self.outputs + usize::from(change)) as f64 + 5.25))
			.ceil() as u64
	}
	pub fn change(&self, value: u64, inputs: usize) -> anyhow::Result<u64> {
		let excess = value
			.checked_sub(self.mix_total())
			.context("coins too small")?;
		if excess > self.fee(true, inputs) + 294 {
			Ok(excess - self.fee(true, inputs))
		} else {
			ensure!(excess >= self.fee(false, inputs), "coins too small");
			Ok(0)
		}
	}
	pub fn validate(&self) -> anyhow::Result<()> {
		ensure!(
			(1..=4).contains(&self.v) && self.network == "blake2b",
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
		ensure!(
			["p2wpkh", "p2tr"].contains(&self.script.as_str())
				&& (1..=10).contains(&self.max_inputs),
			"invalid pool input type or limit"
		);
		ensure!(
			if self.v == 1 {
				self.script == "p2wpkh" && self.max_inputs == 1
			} else {
				true
			},
			"invalid v1 terms"
		);
		ensure!(
			if self.v == 4 {
				(2..=5).contains(&self.outputs)
			} else {
				self.outputs == 1
			},
			"invalid output count"
		);
		if self.v >= 3 {
			ensure!(
				self.creator != self.public_key,
				"separate creator key required"
			);
			bitcoin::secp256k1::XOnlyPublicKey::from_str(&self.creator)?;
			crate::blind::public(&self.blind_key)?;
		}
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
		ensure!(
			k.compressed && self.pubkey.len() == 66,
			"compressed key required"
		);
		Ok(k)
	}
	pub fn script_for(&self, kind: &str) -> anyhow::Result<ScriptBuf> {
		if kind == "p2tr" {
			Ok(ScriptBuf::new_p2tr(
				&Secp256k1::new(),
				self.key()?.inner.x_only_public_key().0,
				None,
			))
		} else {
			self.script()
		}
	}
	pub fn script(&self) -> anyhow::Result<ScriptBuf> {
		Ok(ScriptBuf::new_p2wpkh(&self.key()?.wpubkey_hash()?))
	}
	pub fn validate(&self) -> anyhow::Result<()> {
		ensure!(
			crypto::bytes(&self.txid)?.len() == 32
				&& self.value > 0
				&& self.value <= 2100000000000000,
			"invalid coin"
		);
		self.outpoint()?;
		self.key()?;
		Ok(())
	}
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Seat {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub coins: Vec<Coin>,
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub join_pub: String,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub proofs: Vec<String>,
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
	pub fn all_coins(&self) -> &[Coin] {
		if self.coins.is_empty() {
			std::slice::from_ref(&self.coin)
		} else {
			&self.coins
		}
	}
	pub fn value(&self) -> u64 {
		self.all_coins().iter().map(|c| c.value).sum()
	}
	pub fn check_proofs(&self, terms: &Terms) -> anyhow::Result<()> {
		ensure!(
			self.proofs.len() == self.all_coins().len(),
			"missing ownership proofs"
		);
		bitcoin::secp256k1::XOnlyPublicKey::from_str(&self.join_pub)?;
		for (coin, sig) in self.all_coins().iter().zip(&self.proofs) {
			verify_proof(coin, ownership(&terms.id, &self.join_pub, coin), sig)?;
		}
		Ok(())
	}
	pub fn validate(&self, terms: &Terms) -> anyhow::Result<()> {
		ensure!(
			!self.all_coins().is_empty()
				&& self.all_coins().len() <= terms.max_inputs
				&& self.all_coins()[0] == self.coin,
			"invalid seat coins"
		);
		for c in self.all_coins() {
			c.validate()?;
		}
		ensure!(
			self.change_value == terms.change(self.value(), self.all_coins().len())?,
			"incorrect change"
		);
		if self.change_value == 0 {
			ensure!(self.change_script.is_empty(), "unexpected change script");
		} else {
			ensure!(
				terms.accepts_script(&ScriptBuf::from_bytes(crypto::bytes(&self.change_script)?)),
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
	let names = seat
		.all_coins()
		.iter()
		.map(Coin::name)
		.collect::<Vec<_>>()
		.join(",");
	let v = if seat.all_coins().len() == 1 { 1 } else { 2 };
	crypto::hash(format!(
		"kilojoin/v{v}/change|{pool}|{names}|{}|{}",
		seat.change_script, seat.change_value
	))
}
pub fn seat_mac(token: &str, parts: &[&str]) -> String {
	crypto::hex(&crypto::mac(
		token.as_bytes(),
		format!("kilojoin/v3|{}", parts.join("|")).as_bytes(),
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
	pub script: String,
}
impl Plan {
	pub fn new(
		terms: &Terms,
		seats: &[Seat],
		outputs: &[String],
		mine: &Seat,
		mix: &str,
	) -> anyhow::Result<Self> {
		Self::new_many(terms, seats, outputs, mine, &[mix.to_owned()])
	}
	pub fn new_many(
		terms: &Terms,
		seats: &[Seat],
		outputs: &[String],
		mine: &Seat,
		mixes: &[String],
	) -> anyhow::Result<Self> {
		terms.validate()?;
		ensure!(mixes.len() == terms.outputs, "wrong own output count");
		ensure!(
			(terms.min_peers..=terms.max_peers).contains(&seats.len())
				&& outputs.len() == seats.len() * terms.outputs,
			"incomplete round"
		);
		ensure!(
			seats
				.iter()
				.filter(|s| s.all_coins() == mine.all_coins()
					&& s.change_script == mine.change_script
					&& s.change_value == mine.change_value)
				.count() == 1,
			"our seat was changed"
		);
		ensure!(
			mixes
				.iter()
				.all(|mix| outputs.iter().filter(|s| *s == mix).count() == 1)
				&& mixes.iter().collect::<HashSet<_>>().len() == mixes.len(),
			"our mixed output is missing"
		);
		let mut inputs = HashSet::new();
		let mut input_scripts = HashSet::new();
		for seat in seats {
			seat.validate(terms)?;
			for c in seat.all_coins() {
				ensure!(inputs.insert(c.name()), "duplicate coin");
				input_scripts.insert(c.script_for(&terms.script)?.to_hex_string());
			}
		}
		let mut scripts = HashSet::new();
		let mut mixout = Vec::new();
		let mut changes = Vec::new();
		for script in outputs {
			let spk = ScriptBuf::from_bytes(crypto::bytes(script)?);
			ensure!(
				terms.accepts_script(&spk)
					&& scripts.insert(script.clone())
					&& !input_scripts.contains(script),
				"invalid or reused mixed output"
			);
			mixout.push(TxOut {
				value: Amount::from_sat(terms.denomination),
				script_pubkey: spk,
			});
		}
		for s in seats.iter().filter(|s| s.change_value > 0) {
			ensure!(
				scripts.insert(s.change_script.clone())
					&& !input_scripts.contains(&s.change_script),
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
		let mut coins: Vec<_> = seats
			.iter()
			.flat_map(|s| s.all_coins().iter().cloned())
			.collect();
		coins.sort_by_key(|c| (c.txid.clone(), c.vout));
		let total: u64 = coins.iter().map(|c| c.value).sum();
		let spend: u64 = mixout.iter().map(|o| o.value.to_sat()).sum();
		let paid = total.checked_sub(spend).context("negative fee")?;
		let (iv, ov) = if terms.script == "p2tr" {
			(57.75, 43.0)
		} else {
			(68.0, 31.0)
		};
		let vb = 10.5 + iv * coins.len() as f64 + ov * mixout.len() as f64;
		ensure!(
			paid >= (terms.fee_rate * vb * 0.95).floor() as u64
				&& paid
					<= seats
						.iter()
						.map(|s| terms.fee(true, s.all_coins().len()) + 295)
						.sum::<u64>(),
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
					script_pubkey: c.script_for(&terms.script)?,
				})
			})
			.collect::<anyhow::Result<_>>()?;
		Ok(Self {
			tx,
			coins,
			previous,
			fee: paid,
			script: terms.script.clone(),
		})
	}
	pub fn digest(&self, i: usize) -> anyhow::Result<[u8; 32]> {
		crate::sighash::unified_all(&self.tx, &self.previous, i, self.script == "p2tr")
	}
	pub fn sign(&self, coin: &Coin, key: &SecretKey) -> anyhow::Result<String> {
		let i = self
			.coins
			.iter()
			.position(|c| c == coin)
			.context("missing our coin")?;
		ensure!(
			bitcoin::secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), key)
				== coin.key()?.inner,
			"coin key mismatch"
		);
		if self.script == "p2tr" {
			use bitcoin::key::TapTweak;
			let secp = Secp256k1::new();
			let pair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, key)
				.tap_tweak(&secp, None)
				.to_keypair();
			let mut sig = secp
				.sign_schnorr_no_aux_rand(&Message::from_digest(self.digest(i)?), &pair)
				.serialize()
				.to_vec();
			sig.push(0x21);
			return Ok(crypto::hex(&sig));
		}
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
		if self.script == "p2tr" {
			ensure!(data.len() == 65, "invalid Schnorr length");
			let spk = &self.previous[i].script_pubkey;
			let key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&spk.as_bytes()[2..])?;
			Secp256k1::new().verify_schnorr(
				&bitcoin::secp256k1::schnorr::Signature::from_slice(&data[..64])?,
				&Message::from_digest(self.digest(i)?),
				&key,
			)?;
			return Ok(i);
		}
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
