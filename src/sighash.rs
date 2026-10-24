//! Kilojoin unified SIGHASH_ALL (0x21) for native SegWit and Taproot key-path inputs.
//! The extra zero after locktime is part of the fork's five-byte locktime encoding.
use anyhow::{ensure, Context};
use bitcoin::{
	consensus::serialize,
	hashes::{sha256, Hash},
	Transaction, TxOut,
};

pub fn unified_all(
	tx: &Transaction,
	previous: &[TxOut],
	input: usize,
	taproot: bool,
) -> anyhow::Result<[u8; 32]> {
	ensure!(
		input < tx.input.len() && previous.len() == tx.input.len(),
		"every prevout is required in input order"
	);
	let script = if taproot {
		None
	} else {
		Some(
			previous[input]
				.script_pubkey
				.p2wpkh_script_code()
				.context("P2WPKH input required")?,
		)
	};
	let mut msg = vec![0, 0x21];
	msg.extend(serialize(&tx.version));
	msg.extend(serialize(&tx.lock_time));
	msg.push(0);
	let outpoints: Vec<u8> = tx
		.input
		.iter()
		.flat_map(|i| serialize(&i.previous_output))
		.collect();
	let amounts: Vec<u8> = previous
		.iter()
		.flat_map(|p| p.value.to_sat().to_le_bytes())
		.collect();
	let scripts: Vec<u8> = previous
		.iter()
		.flat_map(|p| serialize(&p.script_pubkey))
		.collect();
	let sequences: Vec<u8> = tx
		.input
		.iter()
		.flat_map(|i| serialize(&i.sequence))
		.collect();
	let outputs: Vec<u8> = tx.output.iter().flat_map(serialize).collect();
	for field in [&outpoints, &amounts, &scripts, &sequences, &outputs] {
		msg.extend(sha256::Hash::hash(field).to_byte_array());
	}
	msg.push(if taproot { 2 } else { 1 }); // witness-v0 execution context
	msg.extend(u32::try_from(input)?.to_le_bytes());
	if let Some(script) = script {
		msg.extend(serialize(&script));
	}
	if taproot { msg.push(0); } // Explicit no-annex execution field.
	let tag = sha256::Hash::hash(b"UnifiedSighash").to_byte_array();
	let mut tagged = tag.to_vec();
	tagged.extend(tag);
	tagged.extend(msg);
	Ok(sha256::Hash::hash(&tagged).to_byte_array())
}
