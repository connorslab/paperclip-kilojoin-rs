// Kilojoin v3/v4 authenticated control and unlinkable output registration.
impl Round {
	fn reply_public(&self) -> &str {
		if self.terms.v >= 3 {
			&self.terms.creator
		} else {
			&self.terms.public_key
		}
	}
	fn reply_secret(&self) -> anyhow::Result<&str> {
		if self.terms.v >= 3 {
			self.creator_secret.as_deref()
		} else {
			self.pool_secret.as_deref()
		}
		.context("missing reply key")
	}
	/// The host must verify these coins against its chain backend before handle(..., true).
	pub fn verification_coins(&self, e: &Event) -> anyhow::Result<Vec<Coin>> {
		let m = self.decode(e)?;
		ensure!(!self.seen.contains(&e.id), "replayed event");
		let typ = m["type"].as_str().unwrap_or("");
		let seats = if typ == "join"
			&& self.creator
			&& self.phase == "open"
			&& !self.joins.contains_key(&e.pubkey)
		{
			let mut s: Seat = serde_json::from_value(m["seat"].clone())?;
			s.validate(&self.terms)?;
			s.join_pub = e.pubkey.clone();
			s.proofs = if s.all_coins().len() == 1
				&& m["proofs"].as_array().is_none_or(|a| a.is_empty())
			{
				vec![m["proof"].as_str().context("missing proof")?.into()]
			} else {
				serde_json::from_value(m["proofs"].clone())?
			};
			s.check_proofs(&self.terms)?;
			protocol::verify_proof(
				&s.coin,
				protocol::change_hash(&self.terms.id, &s),
				m["change_sig"].as_str().context("missing change proof")?,
			)?;
			vec![s]
		} else if self.terms.v >= 3
			&& e.pubkey == self.terms.creator
			&& ["roster", "closing"].contains(&typ)
		{
			let seats: Vec<Seat> = serde_json::from_value(m["seats"].clone())?;
			self.validate_seats(&seats)?;
			seats
		} else {
			return Ok(vec![]);
		};
		Ok(seats
			.iter()
			.flat_map(|s| s.all_coins().iter().cloned())
			.collect())
	}
	fn token_for(&self, hash: &str) -> Option<&str> {
		if hash == self.mine.token_hash {
			Some(&self.token)
		} else {
			self.joins
				.values()
				.find(|t| protocol::token_hash(t) == hash)
				.map(String::as_str)
		}
	}
	fn modern_close(&mut self, now: u64) -> anyhow::Result<()> {
		let vote = crypto::hex(&crypto::random(8));
		if self.creator {
			self.channel(
				json!({"type":"vote_open","by":self.mine.token_hash,"vote_id":vote}),
				now,
			)
		} else {
			self.channel(json!({"type":"close_request","token_hash":self.mine.token_hash,"vote_id":vote,"mac":protocol::seat_mac(&self.token,&["close",&vote])}),now)
		}
	}
	fn modern_vote(&mut self, accept: bool, now: u64) -> anyhow::Result<()> {
		self.channel(json!({"type":"vote","token_hash":self.mine.token_hash,"vote_id":self.vote,"accept":accept,"mac":protocol::seat_mac(&self.token,&["vote",&self.vote,if accept {"true"} else {"false"}])}),now)?;
		self.voted = self.vote.clone();
		if !accept && !self.creator {
			self.abort_local("You left the round");
		}
		Ok(())
	}
	fn member_message(&mut self, m: &Value, at: u64, now: u64) -> anyhow::Result<()> {
		let typ = m["type"].as_str().unwrap_or("");
		if ["sig", "tx", "abort"].contains(&typ) {
			return self.channel_message(m, at, now);
		}
		if !self.creator || !["close_request", "vote", "leave", "blind"].contains(&typ) {
			return Ok(());
		}
		let th = m["token_hash"].as_str().context("missing token hash")?;
		ensure!(
			self.seats.iter().any(|s| s.token_hash == th),
			"unknown member"
		);
		let token = self.token_for(th).context("unknown seat token")?.to_owned();
		let vote = m["vote_id"].as_str().unwrap_or("");
		let blinded: Vec<String> = if typ == "blind" {
			if self.terms.v == 4 {
				serde_json::from_value(m["blinded"].clone())?
			} else {
				vec![m["blinded"]
					.as_str()
					.context("missing blinded request")?
					.into()]
			}
		} else {
			vec![]
		};
		let digest = if typ == "blind" {
			ensure!(
				blinded.len() == self.terms.outputs && blinded.iter().all(|s| s.len() <= 1024),
				"invalid blind request size"
			);
			crypto::hex(&crypto::hash(
				blinded
					.iter()
					.map(|s| crypto::bytes(s))
					.collect::<anyhow::Result<Vec<_>>>()?
					.concat(),
			))
		} else {
			String::new()
		};
		let parts = match typ {
			"close_request" => vec!["close", vote],
			"vote" => vec![
				"vote",
				vote,
				if m["accept"].as_bool().context("missing vote")? {
					"true"
				} else {
					"false"
				},
			],
			"leave" => vec!["leave"],
			_ => vec![
				"blind",
				m["round_id"].as_str().context("missing round")?,
				&digest,
			],
		};
		let expected = protocol::seat_mac(&token, &parts);
		let got = m["mac"].as_str().context("missing MAC")?;
		ensure!(
			got.len() == expected.len()
				&& got
					.bytes()
					.zip(expected.bytes())
					.fold(0u8, |a, (b, c)| a | (b ^ c))
					== 0,
			"invalid member MAC"
		);
		match typ {
			"close_request" if self.phase == "open" && self.seats.len() >= self.terms.min_peers => {
				ensure!(crypto::bytes(vote)?.len() == 8, "invalid vote");
				self.channel(json!({"type":"vote_open","by":th,"vote_id":vote}), now)?;
			}
			"vote" | "leave" => {
				let mut old = m.clone();
				old["token"] = json!(token);
				self.channel_message(&old, at, now)?;
			}
			"blind" if self.phase == "closing" && m["round_id"] == self.round_id => {
				ensure!(
					self.round.iter().any(|s| s.token_hash == th),
					"seat not in round"
				);
				let signatures = if let Some((previous, sigs)) = self.blind_answers.get(th) {
					ensure!(
						*previous == blinded,
						"seat already blinded different messages"
					);
					sigs.clone()
				} else {
					let secret = self.blind_secret.as_deref().context("missing blind key")?;
					let sigs = blinded
						.iter()
						.map(|b| crate::blind::sign(secret, b))
						.collect::<anyhow::Result<Vec<_>>>()?;
					self.blind_answers
						.insert(th.into(), (blinded, sigs.clone()));
					sigs
				};
				let mut reply =
					json!({"type":"blind_sig","token_hash":th,"round_id":self.round_id});
				if self.terms.v == 4 {
					reply["sigs"] = json!(signatures);
				} else {
					reply["sig"] = json!(signatures[0]);
				}
				self.channel(reply, now)?;
			}
			_ => {}
		}
		Ok(())
	}
	fn modern_message(&mut self, m: &Value, at: u64, now: u64) -> anyhow::Result<()> {
		match m["type"].as_str().unwrap_or("") {
			"blind_sig"
				if self.phase == "closing"
					&& m["round_id"] == self.round_id
					&& m["token_hash"] == self.mine.token_hash =>
			{
				if self.creator || self.blind_requests.iter().all(|b| b.signature.is_some()) {
					return Ok(());
				}
				let sigs: Vec<String> = if self.terms.v == 4 {
					serde_json::from_value(m["sigs"].clone())?
				} else {
					vec![m["sig"].as_str().context("missing blind signature")?.into()]
				};
				ensure!(
					sigs.len() == self.terms.outputs && self.blind_requests.len() == sigs.len(),
					"missing blind signatures"
				);
				for ((script, request), signature) in self
					.mix_scripts()
					.iter()
					.zip(self.blind_requests.iter_mut())
					.zip(sigs)
				{
					request.signature = Some(crate::blind::finalize(
						&self.terms.blind_key,
						script,
						request,
						&signature,
					)?);
					request.at = now + 3 + crypto::random(1)[0] as u64 % 41;
				}
			}
			"outputs" if self.phase == "closing" && m["round_id"] == self.round_id => {
				let scripts: Vec<String> = serde_json::from_value(m["scripts"].clone())?;
				ensure!(
					scripts.len() == self.round.len() * self.terms.outputs,
					"wrong mixed output count"
				);
				self.outputs = scripts.iter().cloned().collect();
				ensure!(
					self.outputs.len() == scripts.len(),
					"duplicate mixed output"
				);
				self.plan()?;
				self.phase = "signing".into();
				self.deadline = now + 1200;
			}
			_ => self.channel_message(m, at, now)?,
		}
		Ok(())
	}
	fn begin_blinding(&mut self, m: &Value, now: u64) -> anyhow::Result<()> {
		let id = m["round_id"].as_str().context("missing round id")?;
		ensure!(crypto::bytes(id)?.len() == 8, "invalid round id");
		self.round_id = id.into();
		self.blind_answers.clear();
		self.registered_outputs.clear();
		self.outputs.clear();
		if self.creator {
			self.registered_outputs.extend(self.mix_scripts());
		} else {
			self.blind_requests = self
				.mix_scripts()
				.iter()
				.map(|s| crate::blind::prepare(&self.terms.blind_key, s))
				.collect::<anyhow::Result<_>>()?;
			self.last_blind = 0;
			self.modern_tick(now)?;
		}
		Ok(())
	}
	fn receive_blind_output(&mut self, m: &Value, now: u64) -> anyhow::Result<()> {
		ensure!(
			self.phase == "closing" && m["round_id"] == self.round_id,
			"wrong output round"
		);
		let script = m["script"].as_str().context("missing output")?;
		ensure!(
			script.len() <= 68
				&& self
					.terms
					.accepts_script(&bitcoin::ScriptBuf::from_bytes(crypto::bytes(script)?)),
			"invalid output script"
		);
		crate::blind::verify(
			&self.terms.blind_key,
			script,
			m["prefix"].as_str().context("missing prefix")?,
			m["sig"].as_str().context("missing signature")?,
		)?;
		self.registered_outputs.insert(script.into());
		ensure!(
			self.registered_outputs.len() <= self.round.len() * self.terms.outputs,
			"too many outputs"
		);
		if self.registered_outputs.len() == self.round.len() * self.terms.outputs {
			self.channel(
				json!({"type":"outputs","round_id":self.round_id,"scripts":self.registered_outputs}),
				now,
			)?;
		}
		Ok(())
	}
	fn modern_tick(&mut self, now: u64) -> anyhow::Result<()> {
		if self.creator && self.phase == "open" && now.saturating_sub(self.last_announcement) >= 600
		{
			self.announce(now)?;
			self.last_announcement = now;
		}
		if self.phase != "closing" || self.creator {
			return Ok(());
		}
		if self.blind_requests.iter().any(|r| r.signature.is_none()) {
			if now.saturating_sub(self.last_blind) >= 30 {
				let blinded = self
					.blind_requests
					.iter()
					.map(|r| r.blinded.clone())
					.collect::<Vec<_>>();
				let digest = crypto::hex(&crypto::hash(
					blinded
						.iter()
						.map(|s| crypto::bytes(s))
						.collect::<anyhow::Result<Vec<_>>>()?
						.concat(),
				));
				let mut m = json!({"type":"blind","token_hash":self.mine.token_hash,"round_id":self.round_id,"mac":protocol::seat_mac(&self.token,&["blind",&self.round_id,&digest])});
				m["blinded"] = if self.terms.v == 4 {
					json!(blinded)
				} else {
					json!(blinded.first().context("missing blinded request")?)
				};
				self.channel(m, now)?;
				self.last_blind = now;
			}
		} else {
			for (index, script) in self.mix_scripts().iter().enumerate() {
				let req = &self.blind_requests[index];
				if !req.sent && now >= req.at {
					let e = Event::message(
						&crypto::secret(),
						&self.terms.creator,
						json!({"type":"output","round_id":self.round_id,"script":script,"prefix":req.prefix,"sig":req.signature}),
						now,
					)?;
					self.enqueue(e, true)?;
					self.blind_requests[index].sent = true;
				}
			}
		}
		Ok(())
	}
}
