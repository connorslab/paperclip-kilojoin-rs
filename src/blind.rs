//! RFC 9474 RSABSSA-SHA384-PSS-Randomized. State is secret and must be persisted privately.
use crate::crypto::{bytes, hex};
use anyhow::{ensure, Context};
use blind_rsa_signatures::{
	BlindSignature, DefaultRng, KeyPair, MessageRandomizer, Options, PublicKey, Secret, SecretKey,
	Signature,
};
use rsa::{BigUint, PublicKeyParts, RsaPublicKey};
use serde::{Deserialize, Serialize};

pub fn public(encoded: &str) -> anyhow::Result<PublicKey> {
	ensure!(encoded.len() <= 1032, "blind key too large");
	let (n, e) = encoded.split_once(':').context("invalid blind key")?;
	let n = BigUint::parse_bytes(n.as_bytes(), 16).context("invalid modulus")?;
	let e = BigUint::parse_bytes(e.as_bytes(), 16).context("invalid exponent")?;
	ensure!(
		(2048..=4096).contains(&n.bits()) && n.bits() % 8 == 0 && e == BigUint::from(65537u32),
		"unsupported blind key"
	);
	Ok(PublicKey(RsaPublicKey::new(n, e)?))
}
pub fn generate() -> anyhow::Result<(String, String)> {
	let pair = KeyPair::generate(&mut DefaultRng, 2048)?;
	Ok((
		format!("{:x}:{:x}", pair.pk.0.n(), pair.pk.0.e()),
		hex(&pair.sk.to_der()?),
	))
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Request {
	pub prefix: String,
	pub blinded: String,
	pub inverse: String,
	pub signature: Option<String>,
	pub at: u64,
	pub sent: bool,
}
pub fn prepare(key: &str, script: &str) -> anyhow::Result<Request> {
	let result = public(key)?.blind(&mut DefaultRng, bytes(script)?, true, &Options::default())?;
	Ok(Request {
		prefix: hex(&result.msg_randomizer.context("missing randomizer")?.0),
		blinded: hex(&result.blind_msg.0),
		inverse: hex(&result.secret.0),
		signature: None,
		at: 0,
		sent: false,
	})
}
pub fn sign(secret: &str, blinded: &str) -> anyhow::Result<String> {
	ensure!(blinded.len() <= 1024, "blinded input too large");
	Ok(hex(&SecretKey::from_der(&bytes(secret)?)?
		.blind_sign(&mut DefaultRng, bytes(blinded)?, &Options::default())?
		.0))
}
pub fn finalize(
	key: &str,
	script: &str,
	request: &Request,
	signature: &str,
) -> anyhow::Result<String> {
	let prefix: [u8; 32] = bytes(&request.prefix)?
		.try_into()
		.map_err(|_| anyhow::anyhow!("invalid prefix"))?;
	Ok(hex(&public(key)?
		.finalize(
			&BlindSignature(bytes(signature)?),
			&Secret(bytes(&request.inverse)?),
			Some(MessageRandomizer(prefix)),
			bytes(script)?,
			&Options::default(),
		)?
		.0))
}
pub fn verify(key: &str, script: &str, prefix: &str, signature: &str) -> anyhow::Result<()> {
	let prefix: [u8; 32] = bytes(prefix)?
		.try_into()
		.map_err(|_| anyhow::anyhow!("invalid prefix"))?;
	public(key)?.verify(
		&Signature(bytes(signature)?),
		Some(MessageRandomizer(prefix)),
		bytes(script)?,
		&Options::default(),
	)?;
	Ok(())
}
