//! NIP-01 / NIP-44 v2 wire compatibility. Never expose wallet keys to the relay.
use anyhow::{ensure, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::{
	hashes::{
		hmac::{Hmac, HmacEngine},
		sha256, Hash, HashEngine,
	},
	secp256k1::{self, Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn bytes(s: &str) -> anyhow::Result<Vec<u8>> {
	ensure!(
		s.len() % 2 == 0
			&& s.len() <= 524288
			&& s.bytes()
				.all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
		"invalid lowercase hex"
	);
	(0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
		.collect()
}
pub fn hash(data: impl AsRef<[u8]>) -> [u8; 32] {
	sha256::Hash::hash(data.as_ref()).to_byte_array()
}
pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
	let mut e = HmacEngine::<sha256::Hash>::new(key);
	e.input(data);
	Hmac::<sha256::Hash>::from_engine(e).to_byte_array()
}
pub fn random(n: usize) -> Vec<u8> {
	let mut data = vec![0; n];
	secp256k1::rand::thread_rng().fill_bytes(&mut data);
	data
}
pub fn secret() -> String {
	hex(&SecretKey::new(&mut secp256k1::rand::thread_rng()).secret_bytes())
}
pub fn key(s: &str) -> anyhow::Result<SecretKey> {
	// Kotlin BigInteger.toString(16) omits leading zeroes, including a leading nibble.
	ensure!(
		!s.is_empty()
			&& s.len() <= 64
			&& s.bytes()
				.all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
		"invalid secret encoding"
	);
	Ok(SecretKey::from_slice(&bytes(&format!("{s:0>64}"))?)?)
}
pub fn public(s: &str) -> anyhow::Result<String> {
	Ok(Keypair::from_secret_key(&Secp256k1::new(), &key(s)?)
		.x_only_public_key()
		.0
		.to_string())
}
pub fn conversation(secret: &str, public: &str) -> anyhow::Result<[u8; 32]> {
	let pk = XOnlyPublicKey::from_slice(&bytes(public)?)?.public_key(secp256k1::Parity::Even);
	let shared = secp256k1::ecdh::shared_secret_point(&pk, &key(secret)?);
	Ok(mac(b"nip44-v2", &shared[..32]))
}
fn message_keys(conv: &[u8; 32], nonce: &[u8]) -> Vec<u8> {
	let mut all = Vec::new();
	let mut last = Vec::new();
	for i in 1..=3 {
		last.extend(nonce);
		last.push(i);
		last = mac(conv, &last).to_vec();
		all.extend(&last);
	}
	all.truncate(76);
	all
}
fn padded(n: usize) -> usize {
	if n <= 32 {
		32
	} else {
		let p = n.next_power_of_two();
		let c = if p <= 256 { 32 } else { p / 8 };
		n.div_ceil(c) * c
	}
}
pub fn encrypt(text: &str, conv: &[u8; 32], nonce: &[u8]) -> anyhow::Result<String> {
	ensure!(
		(1..=65535).contains(&text.len()) && nonce.len() == 32,
		"invalid NIP44 length"
	);
	let mut ct = vec![0; 2 + padded(text.len())];
	ct[..2].copy_from_slice(&(text.len() as u16).to_be_bytes());
	ct[2..2 + text.len()].copy_from_slice(text.as_bytes());
	let keys = message_keys(conv, nonce);
	chacha20::ChaCha20::new_from_slices(&keys[..32], &keys[32..44])
		.map_err(|_| anyhow::anyhow!("invalid cipher key"))?
		.apply_keystream(&mut ct);
	let mut payload = vec![2];
	payload.extend(nonce);
	payload.extend(ct);
	let tag = mac(&keys[44..], &payload[1..]);
	payload.extend(tag);
	Ok(STANDARD.encode(payload))
}
pub fn decrypt(text: &str, conv: &[u8; 32]) -> anyhow::Result<String> {
	ensure!(text.len() <= 90000, "NIP44 payload too large");
	let d = STANDARD.decode(text)?;
	ensure!(d.len() >= 99 && d[0] == 2, "invalid NIP44 payload");
	let keys = message_keys(conv, &d[1..33]);
	let expected = mac(&keys[44..], &d[1..d.len() - 32]);
	ensure!(
		expected
			.iter()
			.zip(&d[d.len() - 32..])
			.fold(0u8, |a, (x, y)| a | (x ^ y))
			== 0,
		"invalid NIP44 MAC"
	);
	let mut p = d[33..d.len() - 32].to_vec();
	chacha20::ChaCha20::new_from_slices(&keys[..32], &keys[32..44])
		.map_err(|_| anyhow::anyhow!("invalid cipher key"))?
		.apply_keystream(&mut p);
	let n = u16::from_be_bytes([p[0], p[1]]) as usize;
	ensure!(
		n > 0 && p.len() == 2 + padded(n) && n + 2 <= p.len(),
		"invalid NIP44 padding"
	);
	Ok(String::from_utf8(p[2..n + 2].to_vec())?)
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
	pub id: String,
	pub pubkey: String,
	pub created_at: u64,
	pub kind: u32,
	pub tags: Vec<Vec<String>>,
	pub content: String,
	pub sig: String,
}
impl Event {
	fn digest(&self) -> [u8; 32] {
		hash(
			json!([
				0,
				self.pubkey,
				self.created_at,
				self.kind,
				self.tags,
				self.content
			])
			.to_string(),
		)
	}
	pub fn tag(&self, name: &str) -> Option<&str> {
		self.tags
			.iter()
			.find(|t| t.first().map(String::as_str) == Some(name))
			.and_then(|t| t.get(1))
			.map(String::as_str)
	}
	pub fn verify(&self) -> anyhow::Result<()> {
		ensure!(
			self.content.len() <= 90000
				&& self.tags.len() <= 16
				&& self
					.tags
					.iter()
					.all(|t| t.len() <= 4 && t.iter().all(|s| s.len() <= 256)),
			"event too large"
		);
		let h = self.digest();
		ensure!(hex(&h) == self.id, "event ID mismatch");
		Secp256k1::new()
			.verify_schnorr(
				&secp256k1::schnorr::Signature::from_slice(&bytes(&self.sig)?)?,
				&secp256k1::Message::from_digest(h),
				&XOnlyPublicKey::from_slice(&bytes(&self.pubkey)?)?,
			)
			.context("invalid event signature")
	}
	pub fn sign(
		secret: &str,
		kind: u32,
		tags: Vec<Vec<String>>,
		content: String,
		now: u64,
	) -> anyhow::Result<Self> {
		let pair = Keypair::from_secret_key(&Secp256k1::new(), &key(secret)?);
		let mut e = Self {
			id: String::new(),
			pubkey: public(secret)?,
			created_at: now,
			kind,
			tags,
			content,
			sig: String::new(),
		};
		let h = e.digest();
		e.id = hex(&h);
		e.sig = Secp256k1::new()
			.sign_schnorr(&secp256k1::Message::from_digest(h), &pair)
			.to_string();
		Ok(e)
	}
	pub fn message(secret: &str, to: &str, value: Value, now: u64) -> anyhow::Result<Self> {
		Self::sign(
			secret,
			2023,
			vec![vec!["p".into(), to.into()]],
			encrypt(&value.to_string(), &conversation(secret, to)?, &random(32))?,
			now,
		)
	}
}
