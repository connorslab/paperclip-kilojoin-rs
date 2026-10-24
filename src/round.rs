// Portions adapted from Kilombino Kilowallet/Kilojoin (Apache-2.0).
// Modified for Paperclip; Paperclip modifications are MIT. See NOTICE and licenses/.
//! Durable round state and outbox. A published signature can never be recalled.
use super::{
	crypto::{self, Event},
	protocol::{self, Coin, Plan, Seat, Terms},
};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
pub struct Outgoing {
	pub event: Event,
	pub isolated: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Round {
	#[serde(default)]
	pub join_proofs: Vec<String>,
	#[serde(default)]
	pub creator_secret: Option<String>,
	#[serde(default)]
	pub blind_secret: Option<String>,
	#[serde(default)]
	pub round_id: String,
	#[serde(default)]
	pub mixes: Vec<String>,
	#[serde(default)]
	pub paths: Vec<String>,
	#[serde(default)]
	pub blind_requests: Vec<crate::blind::Request>,
	#[serde(default)]
	pub blind_answers: BTreeMap<String, (Vec<String>, Vec<String>)>,
	#[serde(default)]
	pub registered_outputs: BTreeSet<String>,
	#[serde(default)]
	pub last_blind: u64,
	#[serde(default)]
	pub last_announcement: u64,
	pub terms: Terms,
	pub relay: String,
	pub tor: bool,
	pub creator: bool,
	pub pool_secret: Option<String>,
	pub join_secret: String,
	pub token: String,
	pub mine: Seat,
	pub path: String,
	pub mix: String,
	pub proof: String,
	pub change_sig: String,
	pub password_key: Option<String>,
	pub password_proof: Option<String>,
	pub phase: String,
	pub reason: String,
	pub seats: Vec<Seat>,
	pub round: Vec<Seat>,
	pub seq: u64,
	pub vote: String,
	pub voted: String,
	pub accepts: BTreeSet<String>,
	pub deadline: u64,
	pub output_at: u64,
	pub output_sent: bool,
	pub outputs: BTreeSet<String>,
	pub signatures: BTreeMap<String, String>,
	pub signed: bool,
	pub txid: Option<String>,
	pub joins: BTreeMap<String, String>,
	pub seen: BTreeSet<String>,
	pub outbox: Vec<Outgoing>,
	pub created: u64,
}
/// Host-selected addresses and connection policy. Never serialize the password.
pub struct RoundConfig {
	pub creator_secret: Option<String>,
	pub blind_secret: Option<String>,
	pub extra_coins: Vec<(Coin, String, bitcoin::secp256k1::SecretKey)>,
	pub extra_mixes: Vec<String>,
	pub terms: Terms,
	pub relay: String,
	pub tor: bool,
	/// Some for a creator, None for a joiner.
	pub pool_secret: Option<String>,
	pub coin: Coin,
	pub coin_path: String,
	pub mix_script: String,
	pub change_script: String,
	pub password: Option<String>,
}

impl Round {
	/// Construct a round without publishing. The host must check/reserve the UTXO,
	/// call start, and durably save the round before releasing any outbox event.
	pub fn new(
		config: RoundConfig,
		coin_key: &bitcoin::secp256k1::SecretKey,
		now: u64,
	) -> anyhow::Result<Self> {
		let RoundConfig {
			creator_secret,
			blind_secret,
			extra_coins,
			extra_mixes,
			terms,
			relay,
			tor,
			pool_secret,
			coin,
			coin_path,
			mix_script,
			change_script,
			password,
		} = config;
		terms.validate()?;
		coin.validate()?;
		ensure!(
			terms.state == "open" && terms.timeout > now && terms.peers < terms.max_peers,
			"pool unavailable"
		);
		ensure!(
			coin.key()?.inner
				== bitcoin::secp256k1::PublicKey::from_secret_key(
					&bitcoin::secp256k1::Secp256k1::new(),
					coin_key
				),
			"wrong coin key"
		);
		ensure!(
			terms.accepts_script(&bitcoin::ScriptBuf::from_bytes(crypto::bytes(&mix_script)?)),
			"P2WPKH mixed output required"
		);
		ensure!(
			mix_script != coin.script()?.to_hex_string(),
			"fresh mixed address required"
		);
		let creator = pool_secret.is_some();
		if let Some(secret) = &pool_secret {
			ensure!(
				crypto::public(secret)? == terms.public_key,
				"pool key mismatch"
			);
		}
		let mut coins = vec![coin.clone()];
		let mut paths = vec![coin_path.clone()];
		let mut keys = vec![*coin_key];
		for (c, p, k) in extra_coins {
			coins.push(c);
			paths.push(p);
			keys.push(k);
		}
		ensure!(coins.len() <= terms.max_inputs, "too many inputs");
		let mut mixes = vec![mix_script.clone()];
		mixes.extend(extra_mixes);
		ensure!(
			mixes.len() == terms.outputs
				&& mixes.iter().collect::<BTreeSet<_>>().len() == mixes.len(),
			"invalid mixed outputs"
		);
		for m in &mixes {
			ensure!(
				terms.accepts_script(&bitcoin::ScriptBuf::from_bytes(crypto::bytes(m)?))
					&& !coins.iter().any(|c| c
						.script_for(&terms.script)
						.is_ok_and(|s| s.to_hex_string() == *m)),
				"invalid or reused mixed output"
			);
		}
		if terms.v >= 3 && creator {
			ensure!(
				creator_secret
					.as_ref()
					.map(|s| crypto::public(s))
					.transpose()?
					.as_ref() == Some(&terms.creator)
					&& blind_secret.is_some(),
				"missing creator keys"
			);
		}
		let change_value = terms.change(coins.iter().map(|c| c.value).sum(), coins.len())?;
		let mut mine = Seat {
			coins: if coins.len() > 1 {
				coins.clone()
			} else {
				vec![]
			},
			join_pub: String::new(),
			proofs: vec![],
			token_hash: String::new(),
			coin,
			change_script: if change_value > 0 {
				change_script
			} else {
				String::new()
			},
			change_value,
		};
		mine.validate(&terms)?;
		ensure!(
			mine.change_script != mix_script
				&& mine.change_script != mine.coin.script()?.to_hex_string(),
			"fresh change address required"
		);
		let join_secret = crypto::secret();
		let joinpub = if creator {
			terms.public_key.clone()
		} else {
			crypto::public(&join_secret)?
		};
		let proofs = coins
			.iter()
			.zip(keys.iter())
			.map(|(c, k)| {
				ensure!(
					c.key()?.inner
						== bitcoin::secp256k1::PublicKey::from_secret_key(
							&bitcoin::secp256k1::Secp256k1::new(),
							k
						),
					"coin key mismatch"
				);
				Ok(protocol::proof(
					k,
					protocol::ownership(&terms.id, &joinpub, c),
				))
			})
			.collect::<anyhow::Result<Vec<_>>>()?;
		let proof = proofs[0].clone();
		if terms.v >= 3 {
			mine.join_pub = joinpub.clone();
			mine.proofs = proofs.clone();
		}
		let change_sig = protocol::proof(coin_key, protocol::change_hash(&terms.id, &mine));
		let pw = if terms.private {
			let password = password.context("private pool password required")?;
			ensure!(
				!password.is_empty() && password.len() <= 256,
				"password length out of range"
			);
			Some(crypto::hash(format!(
				"kilojoin/v1/pw|{}|{password}",
				terms.id
			)))
		} else {
			None
		};
		Ok(Self {
			join_proofs: proofs,
			creator_secret,
			blind_secret,
			round_id: String::new(),
			mixes,
			paths,
			blind_requests: vec![],
			blind_answers: BTreeMap::new(),
			registered_outputs: BTreeSet::new(),
			last_blind: 0,
			last_announcement: now,
			terms,
			relay,
			tor,
			creator,
			pool_secret,
			join_secret,
			token: String::new(),
			mine,
			path: coin_path,
			mix: mix_script,
			proof,
			change_sig,
			password_key: if creator {
				pw.map(|p| crypto::hex(&p))
			} else {
				None
			},
			password_proof: if creator {
				None
			} else {
				pw.map(|p| crypto::hex(&crypto::mac(&p, joinpub.as_bytes())))
			},
			phase: "joining".into(),
			reason: String::new(),
			seats: vec![],
			round: vec![],
			seq: 0,
			vote: String::new(),
			voted: String::new(),
			accepts: BTreeSet::new(),
			deadline: 0,
			output_at: 0,
			output_sent: false,
			outputs: BTreeSet::new(),
			signatures: BTreeMap::new(),
			signed: false,
			txid: None,
			joins: BTreeMap::new(),
			seen: BTreeSet::new(),
			outbox: vec![],
			created: now,
		})
	}

	pub fn mix_scripts(&self) -> Vec<String> {
		if self.mixes.is_empty() {
			vec![self.mix.clone()]
		} else {
			self.mixes.clone()
		}
	}
	pub fn coin_paths(&self) -> Vec<String> {
		if self.paths.is_empty() {
			vec![self.path.clone()]
		} else {
			self.paths.clone()
		}
	}
	pub fn terminal(&self) -> bool {
		["confirmed", "aborted", "rejected"].contains(&self.phase.as_str())
	}
	pub fn locked(&self) -> bool {
		!self.terminal() || (self.signed && self.phase != "confirmed")
	}
	pub fn plan(&self) -> anyhow::Result<Plan> {
		Plan::new_many(
			&self.terms,
			&self.round,
			&self.outputs.iter().cloned().collect::<Vec<_>>(),
			&self.mine,
			&self.mix_scripts(),
		)
	}
	pub(crate) fn enqueue(&mut self, e: Event, isolated: bool) -> anyhow::Result<()> {
		ensure!(
			self.outbox.len() < 128,
			"relay outbox full; reconnect first"
		);
		self.outbox.push(Outgoing { event: e, isolated });
		Ok(())
	}
	pub(crate) fn channel(&mut self, value: Value, now: u64) -> anyhow::Result<()> {
		let e = Event::message(
			if self.terms.v >= 3
				&& [
					"roster",
					"vote_open",
					"reopen",
					"closing",
					"blind_sig",
					"outputs",
				]
				.contains(&value["type"].as_str().unwrap_or(""))
			{
				self.creator_secret
					.as_deref()
					.context("creator key required")?
			} else {
				self.pool_secret.as_deref().context("not welcomed")?
			},
			&self.terms.public_key,
			value.clone(),
			now,
		)?;
		self.enqueue(e, value["type"] == "output")
	}
	pub fn announce(&mut self, now: u64) -> anyhow::Result<()> {
		if !self.creator {
			return Ok(());
		}
		let mut t = self.terms.clone();
		t.peers = self.seats.len();
		t.state = match self.phase.as_str() {
			"open" | "voting" | "joining" => "open",
			"closing" | "signing" => "closing",
			"broadcast" | "confirmed" => "done",
			_ => "aborted",
		}
		.into();
		let e = Event::sign(
			self.pool_secret.as_deref().context("missing pool key")?,
			32022,
			vec![
				vec!["d".into(), t.id.clone()],
				vec!["t".into(), "kilojoin".into()],
				vec!["network".into(), "blake2b".into()],
			],
			serde_json::to_string(&t)?,
			now,
		)?;
		self.enqueue(e, false)
	}
	fn roster(&mut self, now: u64) -> anyhow::Result<()> {
		self.seq = self.seq.checked_add(1).context("sequence overflow")?;
		self.channel(
			json!({"type":"roster","seq":self.seq,"seats":self.seats}),
			now,
		)?;
		self.announce(now)
	}
	pub fn start(&mut self, now: u64) -> anyhow::Result<()> {
		if self.creator {
			self.token = crypto::hex(&crypto::random(16));
			self.mine.token_hash = protocol::token_hash(&self.token);
			self.seats = vec![self.mine.clone()];
			self.phase = "open".into();
			self.roster(now)
		} else {
			let e = Event::message(
				&self.join_secret,
				&self.terms.public_key,
				json!({"type":"join","seat":self.mine,"proof":self.proof,"proofs":if self.join_proofs.is_empty() { vec![self.proof.clone()] } else { self.join_proofs.clone() },"change_sig":self.change_sig,"pw":self.password_proof}),
				now,
			)?;
			self.enqueue(e, false)
		}
	}
	pub fn decode(&self, e: &Event) -> anyhow::Result<Value> {
		e.verify()?;
		ensure!(
			e.kind == 2023 && e.created_at >= self.created.saturating_sub(600),
			"unrelated event"
		);
		let join = crypto::public(&self.join_secret)?;
		let secret = if e.tag("p") == Some(join.as_str()) && e.pubkey == self.reply_public() {
			&self.join_secret
		} else if self.creator
			&& self.terms.v >= 3
			&& e.tag("p") == Some(self.terms.creator.as_str())
		{
			self.creator_secret
				.as_ref()
				.context("missing creator key")?
		} else if e.tag("p") == Some(self.terms.public_key.as_str()) {
			self.pool_secret.as_ref().context("not welcomed")?
		} else {
			anyhow::bail!("wrong recipient")
		};
		Ok(serde_json::from_str(&crypto::decrypt(
			&e.content,
			&crypto::conversation(secret, &e.pubkey)?,
		)?)?)
	}
	pub(crate) fn validate_seats(&self, seats: &[Seat]) -> anyhow::Result<()> {
		ensure!(seats.len() <= self.terms.max_peers, "too many seats");
		let mut names = BTreeSet::new();
		let mut tokens = BTreeSet::new();
		for s in seats {
			s.validate(&self.terms)?;
			if self.terms.v >= 3 {
				s.check_proofs(&self.terms)?;
			}
			ensure!(
				s.all_coins().iter().all(|c| names.insert(c.name()))
					&& crypto::bytes(&s.token_hash)?.len() == 32
					&& tokens.insert(&s.token_hash),
				"duplicate or invalid seat"
			);
		}
		Ok(())
	}
	pub fn handle(&mut self, e: &Event, now: u64, unspent: bool) -> anyhow::Result<()> {
		let message = self.decode(e)?;
		let mut staged = self.clone();
		staged.handle_inner(e, message, now, unspent)?;
		*self = staged;
		Ok(())
	}
	fn handle_inner(&mut self, e: &Event, m: Value, now: u64, unspent: bool) -> anyhow::Result<()> {
		if self.seen.contains(&e.id) || self.terminal() {
			return Ok(());
		}
		ensure!(self.seen.len() < 20000, "round event limit reached");
		ensure!(e.created_at <= now + 120, "future event");
		let joinpub = crypto::public(&self.join_secret)?;
		let typ = m["type"].as_str().unwrap_or("");
		if e.tag("p") == Some(joinpub.as_str()) {
			if self.phase == "joining" && e.pubkey == self.reply_public() {
				if typ == "welcome" {
					let raw = m["pool_secret"].as_str().context("missing pool key")?;
					ensure!(
						!raw.is_empty()
							&& raw.len() <= 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()),
						"invalid pool key"
					);
					let padded = format!("{raw:0>64}");
					let secret = padded.as_str();
					ensure!(
						crypto::public(secret)? == self.terms.public_key,
						"wrong pool key"
					);
					let token = m["token"].as_str().context("missing token")?;
					ensure!(crypto::bytes(token)?.len() == 16, "invalid token");
					self.pool_secret = Some(secret.into());
					self.token = token.into();
					self.mine.token_hash = protocol::token_hash(token);
					self.seq = m["seq"].as_u64().unwrap_or(1).saturating_sub(1);
					self.phase = "open".into();
				} else if typ == "reject" {
					self.phase = "rejected".into();
					self.reason = "Pool rejected the join request.".into();
				}
			}
		} else if self.terms.v >= 3
			&& typ == "output"
			&& self.creator
			&& e.tag("p") == Some(self.terms.creator.as_str())
		{
			self.receive_blind_output(&m, now)?;
		} else if self.terms.v >= 3
			&& e.pubkey == self.terms.creator
			&& e.tag("p") == Some(self.terms.public_key.as_str())
		{
			ensure!(
				[
					"roster",
					"vote_open",
					"reopen",
					"closing",
					"blind_sig",
					"outputs"
				]
				.contains(&typ),
				"unexpected creator message"
			);
			if ["roster", "closing"].contains(&typ) {
				ensure!(unspent, "roster inputs not verified");
			}
			self.modern_message(&m, e.created_at, now)?;
		} else if e.pubkey != self.terms.public_key {
			if self.creator && typ == "join" {
				self.join(e, &m, now, unspent)?;
			}
		} else if self.terms.v >= 3 {
			self.member_message(&m, e.created_at, now)?;
		} else {
			self.channel_message(&m, e.created_at, now)?;
		}
		self.seen.insert(e.id.clone());
		Ok(())
	}
	fn join(&mut self, e: &Event, m: &Value, now: u64, unspent: bool) -> anyhow::Result<()> {
		if self.joins.contains_key(&e.pubkey) {
			return Ok(());
		}
		let check = (|| -> anyhow::Result<Seat> {
			ensure!(
				self.phase == "open"
					&& now <= self.terms.timeout
					&& self.seats.len() < self.terms.max_peers,
				"pool no longer open"
			);
			if let Some(k) = &self.password_key {
				ensure!(
					m["pw"].as_str()
						== Some(
							crypto::hex(&crypto::mac(&crypto::bytes(k)?, e.pubkey.as_bytes()))
								.as_str()
						),
					"incorrect password"
				);
			}
			let mut seat: Seat = serde_json::from_value(m["seat"].clone())?;
			seat.validate(&self.terms)?;
			ensure!(
				!self.seats.iter().any(|s| s
					.all_coins()
					.iter()
					.any(|a| seat.all_coins().iter().any(|b| a.name() == b.name()))),
				"coin already registered"
			);
			let proofs: Vec<String> = if seat.all_coins().len() == 1
				&& m["proofs"].as_array().is_none_or(|a| a.is_empty())
			{
				vec![m["proof"].as_str().context("missing proof")?.into()]
			} else {
				serde_json::from_value(m["proofs"].clone())?
			};
			seat.join_pub = e.pubkey.clone();
			seat.proofs = proofs;
			seat.check_proofs(&self.terms)?;
			if self.terms.v < 3 {
				seat.join_pub.clear();
				seat.proofs.clear();
			}
			protocol::verify_proof(
				&seat.coin,
				protocol::change_hash(&self.terms.id, &seat),
				m["change_sig"].as_str().context("missing change proof")?,
			)?;
			ensure!(unspent, "coin is not unspent");
			Ok(seat)
		})();
		let mut seat = match check {
			Ok(s) => s,
			Err(_) => {
				let event = Event::message(
					self.reply_secret()?,
					&e.pubkey,
					json!({"type":"reject","reason":"Join validation failed or pool unavailable"}),
					now,
				)?;
				return self.enqueue(event, false);
			}
		};
		let token = crypto::hex(&crypto::random(16));
		seat.token_hash = protocol::token_hash(&token);
		self.seats.push(seat);
		self.joins.insert(e.pubkey.clone(), token.clone());
		// Welcome precedes the roster. Replaying the channel after welcome covers relay order.
		let welcome = Event::message(
			self.reply_secret()?,
			&e.pubkey,
			json!({"type":"welcome","pool_secret":self.pool_secret,"token":token,"seq":self.seq+1}),
			now,
		)?;
		self.enqueue(welcome, false)?;
		self.roster(now)?;
		if self.seats.len() == self.terms.max_peers {
			self.request_close(now)?;
		}
		Ok(())
	}
	fn closing(&mut self, seats: Vec<Seat>, now: u64) -> anyhow::Result<()> {
		self.channel(json!({"type":"closing","seats":seats,"deadline":now+300,"round_id":crypto::hex(&crypto::random(8))}), now)
	}
	pub(crate) fn channel_message(&mut self, m: &Value, at: u64, now: u64) -> anyhow::Result<()> {
		match m["type"].as_str().unwrap_or("") {
			"roster" if !self.creator && ["open", "voting"].contains(&self.phase.as_str()) => {
				let seq = m["seq"].as_u64().context("invalid sequence")?;
				if seq > self.seq {
					let seats: Vec<Seat> = serde_json::from_value(m["seats"].clone())?;
					self.validate_seats(&seats)?;
					self.seq = seq;
					self.seats = seats;
					if !self.seats.iter().any(|s| s == &self.mine) {
						self.abort_local("Our seat was removed or changed");
					}
				}
			}
			"close_request" | "vote_open"
				if self.phase == "open" && self.seats.len() >= self.terms.min_peers =>
			{
				let th = if self.terms.v >= 3 {
					m["by"].as_str().context("missing voter")?.into()
				} else {
					protocol::token_hash(m["token"].as_str().context("missing token")?)
				};
				ensure!(
					self.seats.iter().any(|s| s.token_hash == th),
					"unknown voter"
				);
				let vote = m["vote_id"].as_str().context("missing vote")?;
				ensure!(crypto::bytes(vote)?.len() == 8, "invalid vote");
				self.phase = "voting".into();
				self.vote = vote.into();
				self.deadline = at + 600;
				self.accepts.clear();
				self.accepts.insert(th);
			}
			"vote" if self.creator && self.phase == "voting" && m["vote_id"] == self.vote => {
				let th = protocol::token_hash(m["token"].as_str().context("missing token")?);
				ensure!(
					self.seats.iter().any(|s| s.token_hash == th),
					"unknown voter"
				);
				if m["accept"].as_bool() == Some(true) {
					self.accepts.insert(th);
					if self
						.seats
						.iter()
						.all(|s| self.accepts.contains(&s.token_hash))
					{
						self.closing(self.seats.clone(), now)?;
					}
				} else {
					if th != self.mine.token_hash {
						self.seats.retain(|s| s.token_hash != th);
						self.roster(now)?;
					}
					self.channel(json!({"type":"reopen","vote_id":self.vote}), now)?;
				}
			}
			"reopen" if self.phase == "voting" && m["vote_id"] == self.vote => {
				self.phase = "open".into();
				self.vote.clear();
				self.accepts.clear();
			}
			"closing" if ["open", "voting"].contains(&self.phase.as_str()) => {
				let seats: Vec<Seat> = serde_json::from_value(m["seats"].clone())?;
				self.validate_seats(&seats)?;
				ensure!(seats.len() >= self.terms.min_peers, "round below minimum");
				ensure!(
					seats.iter().any(|s| s == &self.mine),
					"our seat missing or changed"
				);
				let deadline = m["deadline"].as_u64().unwrap_or(at + 300);
				ensure!(deadline <= at + 360, "invalid deadline");
				self.round = seats;
				self.phase = "closing".into();
				self.deadline = deadline;
				self.output_at = now + 3 + (crypto::random(1)[0] as u64 % 41);
				if self.terms.v >= 3 {
					self.begin_blinding(m, now)?;
				}
			}
			"output" if self.phase == "closing" => {
				let script = m["script"].as_str().context("missing script")?;
				ensure!(
					bitcoin::ScriptBuf::from_bytes(crypto::bytes(script)?).is_p2wpkh(),
					"invalid output"
				);
				self.outputs.insert(script.into());
				ensure!(self.outputs.len() <= self.round.len(), "too many outputs");
				if self.outputs.len() == self.round.len() {
					self.plan()?;
					self.phase = "signing".into();
					self.deadline = now + 1200;
				}
			}
			"sig" if ["signing", "broadcast", "uncertain"].contains(&self.phase.as_str()) => {
				let name = m["outpoint"].as_str().context("missing input")?;
				let sig = m["sig"].as_str().context("missing signature")?;
				self.plan()?.verify(name, sig)?;
				self.signatures.insert(name.into(), sig.into());
			}
			"tx" if ["signing", "broadcast", "uncertain"].contains(&self.phase.as_str()) => {
				let id = self.plan()?.tx.compute_txid().to_string();
				ensure!(m["txid"] == id, "wrong transaction ID");
				// A peer's claim is not evidence of relay or confirmation.
				self.txid = Some(id);
			}
			"leave" if self.creator && ["open", "voting"].contains(&self.phase.as_str()) => {
				let th = protocol::token_hash(m["token"].as_str().unwrap_or(""));
				if th == self.mine.token_hash {
					return Ok(());
				}
				self.seats.retain(|s| s.token_hash != th);
				self.accepts.remove(&th);
				self.roster(now)?;
				if self.phase == "voting" {
					self.channel(json!({"type":"reopen","vote_id":self.vote}), now)?;
				}
			}
			"abort" if self.phase != "broadcast" => {
				self.abort_local("A participant aborted the round")
			}
			_ => {}
		}
		Ok(())
	}
	pub(crate) fn abort_local(&mut self, reason: &str) {
		self.phase = if self.signed { "uncertain" } else { "aborted" }.into();
		self.reason = reason.into();
	}
	pub fn request_close(&mut self, now: u64) -> anyhow::Result<()> {
		ensure!(
			self.phase == "open" && self.seats.len() >= self.terms.min_peers,
			"not enough participants"
		);
		if self.terms.v >= 3 {
			return self.modern_close(now);
		}
		self.channel(
			json!({"type":"close_request","token":self.token,"vote_id":crypto::hex(&crypto::random(8))}),
			now,
		)
	}
	pub fn vote(&mut self, accept: bool, now: u64) -> anyhow::Result<()> {
		ensure!(
			self.phase == "voting" && self.voted != self.vote,
			"no new vote"
		);
		if self.terms.v >= 3 {
			return self.modern_vote(accept, now);
		}
		self.channel(
			json!({"type":"vote","token":self.token,"vote_id":self.vote,"accept":accept}),
			now,
		)?;
		self.voted = self.vote.clone();
		if !accept && !self.creator {
			self.abort_local("You left the round");
		}
		Ok(())
	}
	pub fn leave(&mut self, now: u64) -> anyhow::Result<()> {
		ensure!(
			!self.signed && !self.terminal(),
			"A released signature cannot be recalled; check the transaction"
		);
		if self.pool_secret.is_some() {
			self.channel(
				if self.creator {
					json!({"type":"abort","reason":"Creator left"})
				} else if self.terms.v >= 3 {
					json!({"type":"leave","token_hash":self.mine.token_hash,"mac":protocol::seat_mac(&self.token,&["leave"])})
				} else { json!({"type":"leave","token":self.token}) },
				now,
			)?;
		}
		self.abort_local("You left the round");
		self.announce(now)
	}
	pub fn tick(&mut self, now: u64) -> anyhow::Result<()> {
		if ["open", "joining"].contains(&self.phase.as_str()) && now > self.terms.timeout {
			self.abort_local("Pool expired");
			self.announce(now)?;
		}
		if self.phase == "voting" && now > self.deadline && self.creator {
			let yes: Vec<_> = self
				.seats
				.iter()
				.filter(|s| self.accepts.contains(&s.token_hash))
				.cloned()
				.collect();
			if yes.len() >= self.terms.min_peers {
				self.closing(yes, now)?;
			} else {
				self.seats.retain(|s| {
					self.accepts.contains(&s.token_hash) || s.token_hash == self.mine.token_hash
				});
				self.roster(now)?;
				self.channel(json!({"type":"reopen","vote_id":self.vote}), now)?;
			}
		}
		if ["closing", "signing"].contains(&self.phase.as_str()) && now > self.deadline + 60 {
			self.abort_local("Round timed out");
		}
		if self.terms.v >= 3 {
			self.modern_tick(now)?;
		}
		if self.terms.v < 3 && self.phase == "closing" && !self.output_sent && now >= self.output_at
		{
			self.channel(json!({"type":"output","script":self.mix}), now)?;
			self.output_sent = true;
		}
		Ok(())
	}
	pub fn signed_message(&mut self, sig: String, now: u64) -> anyhow::Result<()> {
		self.signed_messages(vec![sig], now)
	}
	pub fn signed_messages(&mut self, signatures: Vec<String>, now: u64) -> anyhow::Result<()> {
		ensure!(
			self.phase == "signing" && !self.signed && now <= self.deadline,
			"round is not ready for signing"
		);
		ensure!(
			signatures.len() == self.mine.all_coins().len(),
			"missing own signatures"
		);
		let plan = self.plan()?;
		for (c, sig) in self.mine.all_coins().iter().zip(&signatures) {
			plan.verify(&c.name(), sig)?;
		}
		let own = self.mine.all_coins().to_vec();
		for (c, sig) in own.iter().zip(signatures) {
			self.channel(json!({"type":"sig","outpoint":c.name(),"sig":sig}), now)?;
			self.signatures.insert(c.name(), sig);
		}
		self.signed = true;
		Ok(())
	}
}

include!("round_modern.rs");
