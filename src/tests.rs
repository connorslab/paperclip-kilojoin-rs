use crate::protocol::{change, change_hash, fee, ownership, proof, verify_proof, Plan};
use crate::{
	crypto::{self, bytes, hex, Event},
	protocol::{self, Coin, Seat, Terms},
	round::Round,
};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::Transaction;
use serde_json::{json, Value};
fn vectors() -> Value {
	serde_json::from_str(include_str!("../tests/fixtures/vectors.json")).unwrap()
}
fn terms() -> Terms {
	Terms {
		v: 1,
		network: "blake2b".into(),
		id: "0123456789abcdef".into(),
		public_key: vectors()["pool"]["pool_pub"].as_str().unwrap().into(),
		denomination: 10000,
		fee_rate: 2.0,
		min_peers: 2,
		max_peers: 5,
		private: false,
		timeout: 2000000000,
		state: "open".into(),
		peers: 1,
	}
}
fn fixture() -> (Plan, Vec<Seat>, Vec<String>) {
	let v = vectors();
	let tx: Transaction = deserialize(&bytes(v["transaction"]["raw_tx"].as_str().unwrap()).unwrap()).unwrap();
	let seats = tx
		.input
		.iter()
		.enumerate()
		.map(|(i, input)| Seat {
			token_hash: hex(&[i as u8; 32]),
			coin: Coin {
				txid: input.previous_output.txid.to_string(),
				vout: input.previous_output.vout,
				value: if i == 0 { 50000 } else { 60000 },
				pubkey: hex(input.witness.iter().nth(1).unwrap()),
			},
			change_script: v["transaction"]["outputs_in_order"][if i == 0 { 3 } else { 2 }]["script"]
				.as_str()
				.unwrap()
				.into(),
			change_value: if i == 0 { 39729 } else { 49729 },
		})
		.collect::<Vec<_>>();
	let outputs = tx.output[..2]
		.iter()
		.map(|o| o.script_pubkey.to_hex_string())
		.collect::<Vec<_>>();
	(
		Plan::new(&terms(), &seats, &outputs, &seats[0], &outputs[0]).unwrap(),
		seats,
		outputs,
	)
}
#[test]
fn production_crypto_vectors() {
	let v = vectors();
	let join = &v["join"];
	let pool = &v["pool"];
	let coin: Coin = serde_json::from_value(join["coin"].clone()).unwrap();
	let seat = Seat {
		token_hash: String::new(),
		coin: coin.clone(),
		change_script: join["change_script"].as_str().unwrap().into(),
		change_value: 49729,
	};
	let own = ownership(
		pool["id"].as_str().unwrap(),
		join["join_pub"].as_str().unwrap(),
		&coin,
	);
	assert_eq!(hex(&own), join["ownership_hash"]);
	assert_eq!(hex(&change_hash(&terms().id, &seat)), join["change_hash"]);
	let key = crypto::key(join["coin_secret"].as_str().unwrap()).unwrap();
	assert_eq!(proof(&key, own), join["ownership_sig_der"]);
	assert_eq!(
		proof(&key, change_hash(&terms().id, &seat)),
		join["change_sig_der"]
	);
	verify_proof(&coin, own, join["ownership_sig_der"].as_str().unwrap()).unwrap();
	let pw = crypto::hash(format!("kilojoin/v1/pw|{}|hunter2", terms().id));
	assert_eq!(hex(&pw), join["password_key"]);
	assert_eq!(
		hex(&crypto::mac(&pw, join["join_pub"].as_str().unwrap().as_bytes())),
		join["password_proof"]
	);
	assert_eq!(
		protocol::token_hash(join["token"].as_str().unwrap()),
		join["token_hash"]
	);
	let cv = crypto::conversation(
		pool["pool_secret"].as_str().unwrap(),
		pool["pool_pub"].as_str().unwrap(),
	)
	.unwrap();
	assert_eq!(hex(&cv), v["channel_event"]["conversation_key"]);
	let event: Event = serde_json::from_value(v["channel_event"]["event"].clone()).unwrap();
	event.verify().unwrap();
	let plaintext = v["channel_event"]["plaintext"].as_str().unwrap();
	assert_eq!(crypto::decrypt(&event.content, &cv).unwrap(), plaintext);
	assert_eq!(crypto::encrypt(plaintext, &cv, &[7; 32]).unwrap(), event.content);
	let mut corrupt = event.clone();
	corrupt.content.push('a');
	assert!(corrupt.verify().is_err());
	assert!(crypto::decrypt(&event.content, &[0; 32]).is_err());
}
#[test]
fn production_transaction_vectors_and_rejections() {
	let v = vectors();
	let (plan, seats, outputs) = fixture();
	let t = &v["transaction"];
	assert_eq!(plan.fee, 542);
	assert_eq!(fee(2.0, true), 271);
	assert_eq!(fee(2.0, false), 209);
	assert_eq!(change(10209, 10000, 2.0).unwrap(), 0);
	assert_eq!(hex(&plan.digest(0).unwrap()), t["unified_sighash_input0"]);
	assert_eq!(hex(&plan.digest(1).unwrap()), t["unified_sighash_input1"]);
	assert_eq!(
		plan.sign(
			&seats[1].coin,
			&crypto::key(v["join"]["coin_secret"].as_str().unwrap()).unwrap()
		)
		.unwrap(),
		t["sig_B"]
	);
	let mut tx = plan.tx.clone();
	for (i, name) in ["sig_A", "sig_B"].iter().enumerate() {
		let sig = t[name].as_str().unwrap();
		plan.verify(&seats[i].coin.name(), sig).unwrap();
		tx.input[i].witness =
			bitcoin::Witness::from_slice(&[bytes(sig).unwrap(), bytes(&seats[i].coin.pubkey).unwrap()]);
	}
	assert_eq!(hex(&serialize(&tx)), t["raw_tx"]);
	assert_eq!(tx.compute_txid().to_string(), t["txid"]);
	let mut bad = seats.clone();
	bad[0].change_value -= 1;
	assert!(Plan::new(&terms(), &bad, &outputs, &seats[0], &outputs[0]).is_err());
	let mut bad = outputs.clone();
	bad[1] = bad[0].clone();
	assert!(Plan::new(&terms(), &seats, &bad, &seats[0], &outputs[0]).is_err());
	let mut bad = t["sig_B"].as_str().unwrap().to_string();
	bad.truncate(bad.len() - 2);
	bad.push_str("01");
	assert!(plan.verify(&seats[1].coin.name(), &bad).is_err());
	let mut reversed = seats.clone();
	reversed.reverse();
	let mut reversedout = outputs.clone();
	reversedout.reverse();
	assert_eq!(
		Plan::new(&terms(), &reversed, &reversedout, &seats[0], &outputs[0])
			.unwrap()
			.tx,
		plan.tx
	);
}
fn participant(index: usize) -> Round {
	let (_, seats, outputs) = fixture();
	let key = crypto::key(&hex(&crypto::hash(format!("kilojoin vector key {}", index + 1)))).unwrap();
	Round::new(
		crate::round::RoundConfig {
			terms: terms(),
			relay: "wss://relay.kilombino.com".into(),
			tor: true,
			pool_secret: if index == 0 {
				Some(vectors()["pool"]["pool_secret"].as_str().unwrap().into())
			} else {
				None
			},
			coin: seats[index].coin.clone(),
			coin_path: String::new(),
			mix_script: outputs[index].clone(),
			change_script: seats[index].change_script.clone(),
			password: None,
		},
		&key,
		1791400000,
	)
	.unwrap()
}
fn relay(a: &mut Round, b: &mut Round, time: u64) {
	for _ in 0..30 {
		let mut events = std::mem::take(&mut a.outbox);
		events.extend(std::mem::take(&mut b.outbox));
		if events.is_empty() {
			return;
		}
		for outgoing in events {
			for r in [&mut *a, &mut *b] {
				if r.decode(&outgoing.event).is_ok() {
					r.handle(&outgoing.event, time, true).unwrap();
				}
			}
		}
	}
	panic!("relay failed to settle")
}
#[test]
fn two_peers_replay_restart_vote_sign_and_timeout_without_unlocking() {
	let time = 1791400000;
	let mut a = participant(0);
	let mut b = participant(1);
	a.start(time).unwrap();
	b.start(time).unwrap();
	relay(&mut a, &mut b, time);
	assert_eq!(a.seats.len(), 2);
	assert_eq!(b.seats.len(), 2);
	assert_eq!(a.phase, "open");
	assert_eq!(b.phase, "open");
	// Restore the entire round before the interactive phases.
	b = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
	a.request_close(time + 1).unwrap();
	relay(&mut a, &mut b, time + 1);
	assert_eq!(b.phase, "voting");
	b.vote(true, time + 2).unwrap();
	relay(&mut a, &mut b, time + 2);
	assert_eq!(a.phase, "closing");
	assert_eq!(b.phase, "closing");
	a.tick(time + 45).unwrap();
	b.tick(time + 45).unwrap();
	assert!(a.outbox.iter().any(|e| e.isolated));
	assert!(b.outbox.iter().any(|e| e.isolated));
	let replayed = a.outbox[0].event.clone();
	relay(&mut a, &mut b, time + 45);
	assert_eq!(a.phase, "signing");
	assert_eq!(b.phase, "signing");
	assert_eq!(a.plan().unwrap().tx, b.plan().unwrap().tx);
	let old = b.outputs.clone();
	b.handle(&replayed, time + 46, true).unwrap();
	assert_eq!(old, b.outputs);
	let ka = crypto::key(&hex(&crypto::hash("kilojoin vector key 1"))).unwrap();
	let sig = a.plan().unwrap().sign(&a.mine.coin, &ka).unwrap();
	a.signed_message(sig, time + 46).unwrap();
	// Signature and its outbox must survive a crash before publication.
	a = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
	assert!(a.signed);
	assert!(a.locked());
	assert!(a.leave(time + 47).is_err());
	relay(&mut a, &mut b, time + 46);
	let kb = crypto::key(&hex(&crypto::hash("kilojoin vector key 2"))).unwrap();
	let sig = b.plan().unwrap().sign(&b.mine.coin, &kb).unwrap();
	b.signed_message(sig, time + 47).unwrap();
	relay(&mut a, &mut b, time + 47);
	assert_eq!(a.signatures.len(), 2);
	assert_eq!(b.signatures.len(), 2);
	a.tick(time + 2000).unwrap();
	assert_eq!(a.phase, "uncertain");
	assert!(a.locked());
	assert!(a.locked());
}
#[test]
fn unsigned_timeout_releases_coin_and_changed_seat_cannot_reach_signing() {
	let time = 1791400000;
	let mut a = participant(0);
	a.start(time).unwrap();
	a.tick(2000000001).unwrap();
	assert_eq!(a.phase, "aborted");
	assert!(!a.locked());
	let mut a = participant(0);
	let mut b = participant(1);
	a.start(time).unwrap();
	b.start(time).unwrap();
	relay(&mut a, &mut b, time);
	let mut seats = a.seats.clone();
	seats[1].coin.value += 1;
	let e = Event::message(
		a.pool_secret.as_deref().unwrap(),
		&a.terms.public_key,
		json!({"type":"closing","seats":seats,"deadline":time+300}),
		time,
	)
	.unwrap();
	assert!(b.handle(&e, time, true).is_err());
	assert!(!b.signed);
}
#[test]
fn malformed_announcements_and_crypto_are_bounded() {
	let mut t = terms();
	t.fee_rate = f64::NAN;
	assert!(t.validate().is_err());
	t = terms();
	t.min_peers = 1;
	assert!(t.validate().is_err());
	assert!(crypto::bytes("A0").is_err());
	assert!(crypto::bytes("é").is_err());
	assert!(crypto::decrypt("Ag==", &[0; 32]).is_err());
	let mut e = Event::sign(
		&crypto::secret(),
		32022,
		vec![
			vec!["d".into(), terms().id.clone()],
			vec!["t".into(), "kilojoin".into()],
		],
		serde_json::to_string(&terms()).unwrap(),
		1791400000,
	)
	.unwrap();
	assert!(Terms::event(&e).is_err());
	e.id = hex(&[0; 32]);
	assert!(e.verify().is_err());
}

#[test]
fn kotlin_unpadded_secret_keys_are_accepted_without_relaxing_public_hex() {
	assert_eq!(
		crypto::public("1").unwrap(),
		crypto::public(&format!("{:064x}", 1)).unwrap()
	);
	assert!(crypto::key("0").is_err());
	assert!(crypto::key(&"f".repeat(65)).is_err());
}
