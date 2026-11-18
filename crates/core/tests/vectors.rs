//! Runs the shared golden vectors (testdata/vectors.json, generated from this crate's WASM build
//! by testdata/generate-vectors.mjs) against `passauth_core::site` natively: the Rust API must
//! give exactly what the WASM bindings gave, case by case (so a difference between the two
//! builds, or a vectors.json that is out of date with the code, fails here). Every client runs
//! the same file through its own bindings (extension, iOS and macOS AutoFill, Android).

use std::collections::BTreeMap;

use passauth_core::crypto::{KeyPair, SymmetricKey};
use passauth_core::device_login;
use passauth_core::item::{b64, unb64};
use passauth_core::keys::UnlockedAccount;
use passauth_core::sharing::{
    self, EpochPin, GrandfatherCandidate, IdentityRecord, KeyPins, PublicIdentity,
    RosterMemberInput, SignedRoster, SigningIdentity, VaultObservation,
};
use passauth_core::site::{self, PasskeyLogin, SaveCandidate, SavePlan, UrlMatch};
use serde_json::{Value, json};

fn code(e: passauth_core::Error) -> String {
    e.code().map_or_else(|| e.to_string(), str::to_owned)
}

fn outcome<T: serde::Serialize>(r: passauth_core::Result<T>) -> Value {
    match r {
        Ok(v) => json!({ "expected": v }),
        Err(e) => json!({ "error": code(e) }),
    }
}

/// The `signedSharing` section: every identity, signature, roster, review and check, natively.
#[test]
fn signed_sharing_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let s = &v["signedSharing"];
    let mut accounts: BTreeMap<String, UnlockedAccount> = BTreeMap::new();
    let mut signers: BTreeMap<String, SigningIdentity> = BTreeMap::new();
    for a in s["accounts"].as_array().unwrap() {
        let name = a["name"].as_str().unwrap().to_owned();
        let bytes = unb64(a["sessionBytes"].as_str().unwrap()).unwrap();
        let account = UnlockedAccount {
            account_id: a["id"].as_str().unwrap().into(),
            account_key: SymmetricKey::from_slice(&bytes[..32]).unwrap(),
            keypair: KeyPair::from_secret_bytes(bytes[32..].try_into().unwrap()),
        };
        let record: IdentityRecord = serde_json::from_value(a["record"].clone()).unwrap();
        signers.insert(
            name.clone(),
            account.open_signing_identity(&record).unwrap(),
        );
        accounts.insert(name, account);
    }
    let who = |name: &Value, legacy: bool| -> PublicIdentity {
        let name = name.as_str().unwrap();
        if legacy {
            accounts[name].legacy_identity()
        } else {
            signers[name].public()
        }
    };
    let vault_id = s["vault"]["id"].as_str().unwrap();
    let alice = &accounts["alice"];
    let wrap = |name: &str| s["vault"][name].as_str().unwrap();
    let vault_key = alice
        .open_vault_key(vault_id, 0, wrap("wrappedKeyV2"), false)
        .unwrap();
    let second_key = alice
        .open_vault_key(vault_id, 0, wrap("secondKeyV2"), false)
        .unwrap();
    for c in s["openings"].as_array().unwrap() {
        let got = outcome(
            alice
                .open_vault_key(
                    vault_id,
                    c["keyEpoch"].as_u64().unwrap(),
                    wrap(c["wrap"].as_str().unwrap()),
                    c["legacyAllowed"].as_bool().unwrap(),
                )
                .and_then(|k| sharing::key_id(&k, vault_id)),
        );
        assert_eq!(got, only_result(c), "opening {c}");
    }
    assert_eq!(
        json!(sharing::key_id(&vault_key, vault_id).unwrap()),
        s["keyIds"]["first"]
    );
    assert_eq!(
        json!(sharing::key_id(&second_key, vault_id).unwrap()),
        s["keyIds"]["second"]
    );

    // XEdDSA: the fixed-nonce vector computed independently by the generator.
    let x = &s["xeddsa"];
    let secret: [u8; 32] = unhex(x["secret"].as_str().unwrap()).try_into().unwrap();
    let z: [u8; 64] = unhex(x["z"].as_str().unwrap()).try_into().unwrap();
    let message = x["message"].as_str().unwrap().as_bytes();
    let sig = sharing::xeddsa_sign(&secret, message, &z);
    assert_eq!(json!(b64(&sig)), x["signature"]);
    let u: [u8; 32] = unb64(x["publicKey"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        json!(b64(&sharing::xeddsa_public_key(&u).unwrap())),
        x["edwardsKey"]
    );
    assert!(sharing::xeddsa_verify(&u, message, &sig));

    for i in s["identities"].as_array().unwrap() {
        let name = &i["name"];
        let public = who(name, false);
        assert_eq!(json!(public), i["publicIdentity"], "{name}");
        assert_eq!(json!(who(name, true)), i["legacyIdentity"], "{name}");
        let v = public.verify().unwrap();
        assert_eq!(json!(v.hash_b64()), i["hash"]);
        assert_eq!(json!(b64(&v.legacy_hash())), i["legacyHash"]);
        assert_eq!(json!(v.fingerprint()), i["fingerprint"]);
        let pk: [u8; 32] = v.public_key();
        assert_eq!(
            json!(b64(&sharing::xeddsa_public_key(&pk).unwrap())),
            i["edwardsKey"]
        );
        let ed: [u8; 32] = unb64(public.signing_key.as_deref().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            json!(hex(&sharing::identity_statement(v.user_id(), &pk, &ed))),
            i["statement"]
        );
    }
    let forged: PublicIdentity = serde_json::from_value(s["forgedUpgrade"].clone()).unwrap();
    assert!(matches!(
        forged.verify(),
        Err(passauth_core::Error::BadSignature)
    ));
    for c in s["shares"].as_array().unwrap() {
        let to = who(&c["recipient"], c["recipientLegacy"].as_bool().unwrap());
        let signer = &signers[c["signer"].as_str().unwrap()];
        let (role, epoch, sealed) = (
            c["role"].as_str().unwrap(),
            c["keyEpoch"].as_u64().unwrap(),
            c["sealedKey"].as_str().unwrap(),
        );
        let sig = signer
            .sign_share(vault_id, &to, role, epoch, sealed)
            .unwrap();
        assert_eq!(json!(sig), c["signature"]);
        let bytes = sharing::share_statement(&sharing::ShareStatement {
            vault_id,
            recipient_id: &to.user_id,
            recipient_identity: &to.verify().unwrap().hash(),
            role,
            key_epoch: epoch,
            sealed_key: sealed,
            signer_id: signer.user_id(),
        })
        .unwrap();
        assert_eq!(json!(hex(&bytes)), c["statement"]);
        sharing::verify_share(vault_id, &to, role, epoch, sealed, &signer.public(), &sig).unwrap();
    }

    // Rosters: valid ones signed again through review + sign; rogue ones only parsed.
    let mut rosters: BTreeMap<String, String> = BTreeMap::new();
    let pins: KeyPins = serde_json::from_value(s["keyPins"].clone()).unwrap();
    let inputs = |members: &Value| -> Vec<RosterMemberInput> {
        members
            .as_array()
            .unwrap()
            .iter()
            .map(|m| RosterMemberInput {
                identity: who(&m[0], m[2].as_bool().unwrap_or(false)),
                role: m[1].as_str().unwrap().into(),
                email: m[3].as_str().map(str::to_owned),
            })
            .collect()
    };
    for r in s["rosters"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap().to_owned();
        let parsed = SignedRoster::parse(r["json"].as_str().unwrap()).unwrap();
        let signer = &signers[r["signer"].as_str().unwrap()];
        assert_eq!(
            json!(hex(&parsed.signed_bytes(&signer.identity_hash()).unwrap())),
            r["signedBytes"]
        );
        assert_eq!(
            json!(parsed.hash().unwrap()),
            r["hash"],
            "roster {name}'s hash"
        );
        if !r["rogue"].as_bool().unwrap() {
            let previous = r["previous"]
                .as_str()
                .map(|p| SignedRoster::parse(&rosters[p]).unwrap());
            let members = inputs(&r["members"]);
            let review = sharing::roster_review(
                vault_id,
                previous.as_ref(),
                &signer.public(),
                &members,
                &KeyPins::default(),
            )
            .unwrap();
            let signed = signer
                .sign_roster(
                    &vault_key,
                    vault_id,
                    previous.as_ref(),
                    r["keyEpoch"].as_u64().unwrap(),
                    &members,
                    &review.digest,
                )
                .unwrap();
            assert_eq!(json!(signed.to_json().unwrap()), r["json"], "{name}");
            assert!(signed.commits_to(vault_id, &vault_key).unwrap());
        }
        rosters.insert(name, r["json"].as_str().unwrap().into());
    }
    let parse = |name: &Value| -> Option<SignedRoster> {
        name.as_str()
            .map(|n| SignedRoster::parse(&rosters[n]).unwrap())
    };
    let name_of = |json: &str| -> String {
        rosters
            .iter()
            .find(|(_, j)| j.as_str() == json)
            .map_or_else(|| json.to_owned(), |(n, _)| n.clone())
    };
    for c in s["commitments"].as_array().unwrap() {
        assert_eq!(
            json!(
                sharing::key_commitment(&vault_key, vault_id, c["keyEpoch"].as_u64().unwrap())
                    .unwrap()
            ),
            c["commitment"]
        );
    }
    for c in s["chains"].as_array().unwrap() {
        let newer: Vec<SignedRoster> = c["newer"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| parse(n).unwrap())
            .collect();
        let got = outcome(
            sharing::verify_roster_chain(
                c["vault"].as_str().unwrap(),
                parse(&c["trusted"]).as_ref(),
                &newer,
                &parse(&c["latest"]).unwrap(),
            )
            .and_then(|r| r.to_json())
            .map(|j| name_of(&j)),
        );
        assert_eq!(got, only_result(c), "chain {c}");
    }
    for c in s["heads"].as_array().unwrap() {
        let got = outcome(sharing::roster_head(
            c["vault"].as_str().unwrap(),
            parse(&c["remembered"]).as_ref(),
            parse(&c["latest"]).as_ref(),
        ));
        assert_eq!(got, only_result(c), "head {c}");
    }
    let plain = |members: &Value| -> Vec<RosterMemberInput> {
        members
            .as_array()
            .unwrap()
            .iter()
            .map(|m| RosterMemberInput {
                identity: who(&m[0], m[2].as_bool().unwrap_or(false)),
                role: m[1].as_str().unwrap().into(),
                email: None,
            })
            .collect()
    };
    for c in s["memberDiffs"].as_array().unwrap() {
        let roster = parse(&c["roster"]).unwrap();
        assert_eq!(
            json!(sharing::compare_members(&roster, &plain(&c["members"]))),
            c["expected"]
        );
    }
    for c in s["rosterRoles"].as_array().unwrap() {
        let roster = parse(&c["roster"]).unwrap();
        let id = who(&c["identity"][0], c["identity"][1].as_bool().unwrap());
        assert_eq!(json!(roster.member_role(&id).unwrap()), c["member"], "{c}");
        assert_eq!(json!(roster.signer_role(&id).unwrap()), c["signer"], "{c}");
    }

    // Key pins.
    let rebuilt = KeyPins::default()
        .set(&who(&json!("bob"), false), "bob@example.com", true, 1000)
        .unwrap()
        .set(
            &who(&json!("carol"), true),
            "carol@example.com",
            false,
            1000,
        )
        .unwrap();
    assert_eq!(rebuilt, pins);
    for c in s["pinChecks"].as_array().unwrap() {
        let id = who(&c["identity"][0], c["identity"][1].as_bool().unwrap());
        assert_eq!(
            json!(pins.check_identity(&id, c["email"].as_str()).unwrap()),
            c["expected"]
        );
    }
    for c in s["emails"].as_array().unwrap() {
        assert_eq!(
            json!(sharing::normalize_email(c["email"].as_str().unwrap())),
            c["expected"]
        );
    }
    for c in s["reviews"].as_array().unwrap() {
        let previous = parse(&c["previous"]);
        let signer = &signers[c["signer"].as_str().unwrap()];
        let review = sharing::roster_review(
            vault_id,
            previous.as_ref(),
            &signer.public(),
            &inputs(&c["members"]),
            &pins,
        )
        .unwrap();
        assert_eq!(json!(review), c["expected"], "review {}", c["name"]);
    }

    // Key epochs.
    for c in s["epochChecks"].as_array().unwrap() {
        let pinned: Option<EpochPin> = serde_json::from_value(c["pinned"].clone()).unwrap();
        let current: EpochPin = serde_json::from_value(c["current"].clone()).unwrap();
        assert_eq!(
            json!(sharing::epoch_check(pinned.as_ref(), &current)),
            c["expected"]
        );
    }
    let ep = |k: &SymmetricKey, e: u64| EpochPin::of(k, vault_id, e).unwrap();
    let roster_hash = |name: &str| {
        s["rosters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap()["hash"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    // Keys this device gave the vault itself, recorded as its sealed row.
    let record = |p: &KeyPins, current: &EpochPin, roster: Option<(u64, &str)>| {
        let hash = roster.map(|(_, name)| roster_hash(name));
        p.record_rotation(
            vault_id,
            "sealed",
            current,
            roster.map(|(v, _)| v),
            hash.as_deref(),
        )
    };
    let with_epoch = record(&pins, &ep(&vault_key, 1), Some((2, "v2"))).unwrap();
    assert_eq!(json!(with_epoch), s["keyPinsWithEpoch"]);
    for c in s["pinsEpochChecks"].as_array().unwrap() {
        let current: EpochPin = serde_json::from_value(c["current"].clone()).unwrap();
        assert_eq!(
            json!(with_epoch.check_epoch(vault_id, &current, c["rosterVersion"].as_u64())),
            c["expected"]
        );
    }
    let raised = record(&with_epoch, &ep(&second_key, 2), Some((3, "v3"))).unwrap();
    assert_eq!(json!(raised), s["keyPinsRaised"]);
    let other_device = record(&KeyPins::default(), &ep(&second_key, 2), None).unwrap();
    assert_eq!(
        json!(with_epoch.merge(&other_device).unwrap().epochs),
        s["mergedEpochs"]
    );
    let left = raised.leave(vault_id, 3, 2000).unwrap();
    assert_eq!(json!(left), s["keyPinsLeft"]);
    let candidates = [GrandfatherCandidate {
        vault_id: vault_id.to_owned(),
        key_id: ep(&vault_key, 0).key_id,
    }];
    let grandfathered = pins.grandfather(&candidates, true).unwrap();
    assert_eq!(json!(grandfathered), s["keyPinsGrandfathered"]);
    let withheld = pins.grandfather(&candidates, false).unwrap();
    assert_eq!(json!(withheld), s["keyPinsWithheld"]);
    let unsigned = record(&grandfathered, &ep(&vault_key, 1), None).unwrap();
    assert_eq!(json!(unsigned), s["keyPinsUnsigned"]);
    let roster_max = with_epoch
        .observe(&VaultObservation {
            vault_id: vault_id.to_owned(),
            key_kind: "sealed".into(),
            key: Some(ep(&vault_key, 1)),
            roster_version: Some(3),
            roster_hash: Some(roster_hash("v3")),
            chain_hashes: None,
            signed_share: true,
            paused: false,
            invitation: false,
            bound_wrap: false,
        })
        .unwrap()
        .pins;
    assert_eq!(json!(roster_max), s["keyPinsRosterMax"]);
    let own_vault = KeyPins::default()
        .observe(&VaultObservation {
            vault_id: vault_id.to_owned(),
            key_kind: "account".into(),
            key: Some(ep(&vault_key, 1)),
            roster_version: None,
            roster_hash: None,
            chain_hashes: None,
            signed_share: false,
            paused: false,
            invitation: false,
            bound_wrap: false,
        })
        .unwrap()
        .pins;
    assert_eq!(json!(own_vault), s["keyPinsOwn"]);
    let bound = own_vault
        .observe(&VaultObservation {
            bound_wrap: true,
            ..serde_json::from_value(json!({
                "vault_id": vault_id, "key_kind": "account", "key": ep(&vault_key, 1),
                "roster_version": null, "signed_share": false, "paused": false
            }))
            .unwrap()
        })
        .unwrap()
        .pins;
    assert_eq!(json!(bound), s["keyPinsBound"]);
    let sets: BTreeMap<&str, KeyPins> = [
        ("none", KeyPins::default()),
        ("withEpoch", with_epoch),
        ("raised", raised),
        ("left", left),
        ("grandfathered", grandfathered),
        ("withheld", withheld),
        ("unsigned", unsigned),
        ("rosterMax", roster_max),
        ("own", own_vault),
        ("bound", bound),
    ]
    .into_iter()
    .collect();
    for c in s["admissions"].as_array().unwrap() {
        let o: VaultObservation = serde_json::from_value(c["observation"].clone()).unwrap();
        assert_eq!(
            json!(sets[c["pins"].as_str().unwrap()].admit(&o).unwrap()),
            c["expected"],
            "admission {c}"
        );
    }
    for c in s["accepts"].as_array().unwrap() {
        let o: VaultObservation = serde_json::from_value(c["observation"].clone()).unwrap();
        let got = sets[c["pins"].as_str().unwrap()].accept(&o);
        match (&got, c.get("expected"), c.get("error")) {
            (Ok(p), Some(e), _) => assert_eq!(&json!(p), e, "accept {c}"),
            (Err(err), _, Some(e)) => assert_eq!(json!(err.code()), *e, "accept {c}"),
            _ => panic!("accept {c}: {got:?}"),
        }
    }
    for c in s["merges"].as_array().unwrap() {
        let base: KeyPins = serde_json::from_value(c["base"].clone()).unwrap();
        let ours: KeyPins = serde_json::from_value(c["ours"].clone()).unwrap();
        assert_eq!(
            outcome(base.merge(&ours)),
            only_result(c),
            "merge {}",
            c["name"]
        );
    }
    for c in s["mergesLastKnown"].as_array().unwrap() {
        let base: KeyPins = serde_json::from_value(c["base"].clone()).unwrap();
        let last: KeyPins = serde_json::from_value(c["lastKnown"].clone()).unwrap();
        assert_eq!(
            outcome(base.merge_last_known(&last)),
            only_result(c),
            "last-known merge {}",
            c["name"]
        );
    }
    for c in s["declines"].as_array().unwrap() {
        let p = &sets[c["pins"].as_str().unwrap()];
        assert_eq!(
            json!(
                p.decline(
                    c["vaultId"].as_str().unwrap(),
                    c["currentRow"].as_bool().unwrap(),
                    3000
                )
                .unwrap()
            ),
            c["expected"],
            "decline {c}"
        );
    }
    let mut step = sets["grandfathered"].clone();
    for c in s["observations"].as_array().unwrap() {
        let o: VaultObservation = serde_json::from_value(c["observation"].clone()).unwrap();
        let observed = step.observe(&o).unwrap();
        assert_eq!(json!(observed), c["expected"], "observation {c}");
        step = if c["accept"] == true {
            let accepted = step.accept(&o).unwrap();
            assert_eq!(json!(accepted), c["accepted"], "accepted {c}");
            accepted
        } else {
            observed.pins
        };
    }
    for c in s["legacyWraps"].as_array().unwrap() {
        assert_eq!(
            json!(
                sets[c["pins"].as_str().unwrap()]
                    .legacy_wrap_allowed(vault_id, c["keyEpoch"].as_u64().unwrap())
            ),
            c["expected"]
        );
    }
    let own = &s["ownIdentity"];
    assert_eq!(json!(b64(&signers["alice"].identity_hash())), own["hash"]);
    let with_own = pins
        .set_own_identity(own["hash"].as_str().unwrap())
        .unwrap();
    assert_eq!(json!(with_own), own["pins"]);
    for c in own["checks"].as_array().unwrap() {
        let p = if c["pins"] == "withOwn" {
            &with_own
        } else {
            &sets["none"]
        };
        assert_eq!(
            json!(p.check_own_identity(c["listed"].as_str())),
            c["expected"]
        );
    }
}

/// A case's `expected` or `error`, as [`outcome`] gives it.
fn only_result(c: &Value) -> Value {
    let mut want = c.clone();
    want.as_object_mut()
        .unwrap()
        .retain(|k, _| k == "expected" || k == "error");
    want
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_default()
}

fn cases<'a>(v: &'a Value, section: &str) -> &'a Vec<Value> {
    let list = v[section]
        .as_array()
        .unwrap_or_else(|| panic!("testdata/vectors.json has no {section} section"));
    assert!(!list.is_empty(), "no {section} vectors");
    list
}

/// The vectors' simplified plan: targets as `{id, vault?}`.
fn simple_plan(plan: &SavePlan) -> Value {
    let targets: Vec<Value> = plan
        .targets()
        .iter()
        .map(|t| match &t.vault {
            Some(v) => json!({"id": t.id, "vault": v}),
            None => json!({"id": t.id}),
        })
        .collect();
    match plan {
        SavePlan::None => json!({"action": "none"}),
        SavePlan::Create { .. } => json!({"action": "create", "targets": targets}),
        SavePlan::Update { reason, target, .. } => {
            json!({"action": "update", "reason": reason, "target": target, "targets": targets})
        }
    }
}

#[test]
fn golden_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors.json");
    let text = std::fs::read_to_string(path).expect("testdata/vectors.json");
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["version"], 2, "vectors.json format");
    assert_eq!(
        v["publicSuffixList"],
        json!(site::public_suffix_list_version()),
        "vectors.json was made with another Public Suffix List: regenerate it"
    );
    let mut diffs: Vec<String> = Vec::new();
    let mut n = 0;
    let mut check = |section: &str, key: String, vector: &Value, native: Value| {
        n += 1;
        if *vector != native {
            diffs.push(format!(
                "{section} {key:?}: vector {vector} → native {native}"
            ));
        }
    };

    for c in cases(&v, "normalizeHost") {
        let host = str_of(c, "host");
        check(
            "normalizeHost",
            host.into(),
            &c["expected"],
            json!(site::normalize_host(host)),
        );
    }
    for c in cases(&v, "baseDomain") {
        let host = str_of(c, "host");
        check(
            "baseDomain",
            host.into(),
            &c["expected"],
            json!(site::base_domain(host)),
        );
    }
    for c in cases(&v, "publicSuffix") {
        let host = str_of(c, "host");
        check(
            "publicSuffix",
            host.into(),
            &c["expected"],
            json!(site::public_suffix(host)),
        );
    }
    for c in cases(&v, "urlMatch") {
        let (page, url, m, d) = (
            str_of(c, "page"),
            str_of(c, "url"),
            str_of(c, "match"),
            str_of(c, "defaultMatch"),
        );
        let allow = c["allowRegex"].as_bool().unwrap();
        // The bindings' rules: an unknown match type never matches, an unknown default is "domain".
        let got = site::parse_url_match(m).is_some_and(|m| {
            site::matches_url(
                page,
                url,
                m,
                site::parse_url_match(d).unwrap_or(UrlMatch::Domain),
                allow,
            )
        });
        check(
            "urlMatch",
            format!("{page}|{url}|{m}|{d}|{allow}"),
            &c["expected"],
            json!(got),
        );
    }
    for c in cases(&v, "resolveMatch") {
        let (url, m, d) = (
            str_of(c, "url"),
            str_of(c, "match"),
            str_of(c, "defaultMatch"),
        );
        // The bindings' rules: an unknown match type is "never", an unknown default "domain".
        let got = site::parse_url_match(m).map_or(UrlMatch::Never, |m| {
            site::resolve_match(url, m, site::parse_url_match(d).unwrap_or(UrlMatch::Domain))
        });
        check(
            "resolveMatch",
            format!("{url}|{m}|{d}"),
            &c["expected"],
            json!(got.as_str()),
        );
    }
    for c in cases(&v, "downgrade") {
        let (page, url, m) = (str_of(c, "page"), str_of(c, "url"), str_of(c, "match"));
        let got = site::downgrade(
            page,
            url,
            site::parse_url_match(m).unwrap_or(UrlMatch::Domain),
        );
        check(
            "downgrade",
            format!("{page}|{url}|{m}"),
            &c["expected"],
            json!(got),
        );
    }
    for c in cases(&v, "regexError") {
        let pattern = str_of(c, "pattern");
        check(
            "regexError",
            pattern.chars().take(40).collect(),
            &c["expected"],
            json!(site::regex_error(pattern)),
        );
    }
    for c in cases(&v, "regexWarning") {
        let pattern = str_of(c, "pattern");
        check(
            "regexWarning",
            pattern.chars().take(40).collect(),
            &c["expected"],
            json!(site::regex_warning(pattern)),
        );
    }
    for c in cases(&v, "savePlan") {
        let candidates: Vec<SaveCandidate> =
            serde_json::from_value(c["candidates"].clone()).unwrap();
        let plan = site::plan_save(&candidates, str_of(c, "typedUser"), str_of(c, "password"));
        check(
            "savePlan",
            str_of(c, "name").into(),
            &c["expected"],
            simple_plan(&plan),
        );
    }
    for c in cases(&v, "passkeyTargets") {
        let logins: Vec<PasskeyLogin> = serde_json::from_value(c["logins"].clone()).unwrap();
        let targets = site::passkey_save_targets(
            &logins,
            str_of(c, "host"),
            str_of(c, "rpId"),
            str_of(c, "userName"),
            str_of(c, "displayName"),
        );
        let simple: Vec<Value> = targets
            .iter()
            .map(|t| match &t.vault {
                Some(v) => json!({"id": t.id, "preferred": t.preferred, "vault": v}),
                None => json!({"id": t.id, "preferred": t.preferred}),
            })
            .collect();
        check(
            "passkeyTargets",
            str_of(c, "name").into(),
            &json!({"expected": c["expected"], "expectedDefault": c["expectedDefault"]}),
            json!({"expected": simple, "expectedDefault": site::passkey_default_target(&targets)}),
        );
    }
    for c in cases(&v, "rpId") {
        let origin = str_of(c, "origin");
        let requested = c["requested"].as_str();
        let vector = match c["expected"].as_str() {
            Some(rp) => json!(rp),
            None => json!({"error": c["error"], "message": c["message"]}),
        };
        let native = match site::effective_rp_id(requested, origin) {
            Ok(rp) => json!(rp),
            Err(e) => json!({"error": "SecurityError", "message": e.message()}),
        };
        check(
            "rpId",
            format!("{origin}|{}", requested.unwrap_or("null")),
            &vector,
            native,
        );
    }

    for c in cases(&v, "loginPhraseChoices") {
        let key = str_of(c, "publicKey");
        let count = c["count"].as_u64().unwrap() as usize;
        check(
            "loginPhraseChoices",
            format!("{key}|{count}"),
            &c["expected"],
            json!(device_login::login_phrase_choices(key, count).unwrap()),
        );
    }

    assert!(
        diffs.is_empty(),
        "{} of {n} cases differ from testdata/vectors.json (regenerate it with node testdata/generate-vectors.mjs if the change is intended):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

/// The `itemRev` section: the edit counter rule (`item_rev_check`) natively, and the counter
/// through encrypt / update / move.
#[test]
fn item_rev_vectors() {
    use passauth_core::item::{EncryptedItem, Item, item_rev_check};
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let r = &v["itemRev"];
    for c in r["checks"].as_array().unwrap() {
        assert_eq!(
            json!(item_rev_check(
                c["remembered"].as_u64(),
                c["served"].as_u64().unwrap()
            )),
            c["expected"],
            "{c}"
        );
    }
    let key = SymmetricKey::generate().unwrap();
    let made = EncryptedItem::encrypt(&Item::default(), "item", "vault", &key).unwrap();
    let first = made.decrypt(&key).unwrap();
    let edited = made.update(&first, &key).unwrap();
    let stale = edited.update(&Item::default(), &key).unwrap();
    let restored = stale.update(&first, &key).unwrap();
    let moved = restored.move_to(&key, "vault", &key).unwrap();
    let chain: Vec<u64> = [made, edited, stale, restored, moved]
        .iter()
        .map(|e| e.decrypt(&key).unwrap().rev)
        .collect();
    assert_eq!(json!(chain), r["chain"]);

    // `limits`: items stored with any `rev` at all open, and save again, natively too.
    let l = &r["limits"];
    let bytes = unb64(str_of(l, "sessionBytes")).unwrap();
    let account = UnlockedAccount {
        account_id: str_of(l, "accountId").into(),
        account_key: SymmetricKey::from_slice(&bytes[..32]).unwrap(),
        keypair: KeyPair::from_secret_bytes(bytes[32..].try_into().unwrap()),
    };
    let vault_id = str_of(l, "vaultId");
    let key = account
        .open_vault_key(
            vault_id,
            l["keyEpoch"].as_u64().unwrap(),
            str_of(l, "wrappedKey"),
            false,
        )
        .unwrap();
    let top = l["top"].as_u64().unwrap();
    assert_eq!(top, passauth_core::item::MAX_ITEM_REV);
    for i in l["items"].as_array().unwrap() {
        let enc: EncryptedItem = serde_json::from_value(i["encrypted"].clone()).unwrap();
        let item = enc.decrypt(&key).unwrap();
        assert_eq!(json!(item.rev), i["reads"], "{i}");
        let written = i["writes"].as_u64().unwrap();
        assert_eq!(written, item.rev + 1);
        for saved in [
            enc.update(&item, &key).unwrap(),
            EncryptedItem::encrypt(&item, &enc.id, vault_id, &key).unwrap(),
            enc.move_to(&key, vault_id, &key).unwrap(),
        ] {
            assert_eq!(saved.decrypt(&key).unwrap().rev, written.min(top), "{i}");
        }
    }
}

/// The `sendV2` section: the password-derived content key and a field sealed by the
/// generator with a fixed nonce, natively.
#[test]
fn send_v2_vectors() {
    use passauth_core::send::{self, SendField, SendKey};
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let s = &v["sendV2"];
    let link = SendKey::from_b64(str_of(s, "key")).unwrap();
    let secrets = send::password_secrets(str_of(s, "password"), str_of(s, "salt")).unwrap();
    assert_eq!(json!(secrets.verifier), s["verifier"]);
    let content = link.content_key(&secrets);
    assert_eq!(json!(content.to_b64()), s["contentKey"]);
    assert_eq!(
        send::open_field(&link, Some(&content), SendField::Data, str_of(s, "data")).unwrap(),
        str_of(s, "text").as_bytes()
    );
    assert!(send::open_field(&link, None, SendField::Data, str_of(s, "data")).is_err());
}

/// The `vaultManifest` section natively: the keys through the fixture's account wraps, every
/// term, the sum, the links, every verdict (with what the device remembers and the log),
/// every write and every start, and the rows no entry point may count.
#[test]
fn vault_manifest_vectors() {
    use passauth_core::manifest::{
        self, Entry, LogEntry, Manifest, ManifestKeys, Row, Seen, data_hash, parse_link,
    };
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let m = &v["vaultManifest"];
    let bytes = unb64(str_of(m, "sessionBytes")).unwrap();
    let account = UnlockedAccount {
        account_id: str_of(m, "accountId").into(),
        account_key: SymmetricKey::from_slice(&bytes[..32]).unwrap(),
        keypair: KeyPair::from_secret_bytes(bytes[32..].try_into().unwrap()),
    };
    let vault_id = str_of(m, "vaultId");
    let epoch = m["keyEpoch"].as_u64().unwrap();
    let key = account
        .open_vault_key(vault_id, epoch, str_of(m, "wrappedKey"), false)
        .unwrap();
    assert_eq!(hex(key.as_bytes()), str_of(m, "vaultKey"));
    let rotated_epoch = m["rotated"]["keyEpoch"].as_u64().unwrap();
    let rotated = account
        .open_vault_key(
            vault_id,
            rotated_epoch,
            str_of(&m["rotated"], "wrappedKey"),
            false,
        )
        .unwrap();
    assert_eq!(hex(rotated.as_bytes()), str_of(&m["rotated"], "vaultKey"));
    let key_of = |c: &Value| match str_of(c, "key") {
        "main" => (&key, epoch),
        "rotated" => (&rotated, rotated_epoch),
        other => panic!("unknown key {other}"),
    };
    let rows = |name: &Value| -> Vec<Entry> {
        serde_json::from_value(m["items"][name.as_str().unwrap()].clone()).unwrap()
    };
    let row_of = |stored: &'_ Value| -> (u64, Option<String>, Option<String>) {
        (
            stored["manifest_seq"].as_u64().unwrap(),
            stored["manifest_prev"].as_str().map(str::to_owned),
            stored["manifest"].as_str().map(str::to_owned),
        )
    };
    let seen_of = |r: &Value| -> Option<Seen> {
        (!r.is_null())
            .then(|| Seen::parse(r["version"].as_u64().unwrap(), str_of(r, "link")).unwrap())
    };
    let keys = ManifestKeys::derive(&key);
    for t in m["terms"].as_array().unwrap() {
        let hash: [u8; 32] = unb64(str_of(t, "dataSha256")).unwrap().try_into().unwrap();
        let term = keys
            .term(str_of(t, "id"), t["trashed"].as_bool().unwrap(), &hash)
            .unwrap();
        assert_eq!(hex(&term), str_of(t, "term"), "{t}");
    }
    let full = rows(&json!("full"));
    for (row, t) in full.iter().zip(m["terms"].as_array().unwrap()) {
        let data = row.data.as_deref().unwrap();
        assert_eq!(b64(&data_hash(data)), str_of(t, "dataSha256"));
    }
    let version = m["version"].as_u64().unwrap();
    let sum = keys.summarize(&full).unwrap().unwrap();
    assert_eq!(
        json!([sum.live, sum.trashed, hex(&sum.acc)]),
        json!([m["live"], m["trashed"], m["acc"]])
    );
    // Every row's link.
    for (name, stored) in m["manifests"].as_object().unwrap() {
        let (seq, prev, sealed) = row_of(stored);
        match (stored["link"].as_str(), prev, sealed) {
            (Some(link), Some(prev), Some(sealed)) => {
                assert_eq!(
                    manifest::row_link(seq, &prev, &sealed).unwrap(),
                    link,
                    "{name}"
                );
            }
            (None, ..) => {}
            other => panic!("{name}: {other:?}"),
        }
    }
    let current = &m["manifests"]["current"];
    let (seq, prev, sealed) = row_of(current);
    let (prev, sealed) = (prev.unwrap(), sealed.unwrap());
    assert_eq!(seq, version);
    let opened = Manifest::open(
        &key,
        vault_id,
        epoch,
        version,
        &parse_link(&prev).unwrap(),
        &sealed,
    )
    .unwrap();
    assert_eq!(opened.summary, sum);
    let current_row = Row {
        seq,
        prev: Some(&prev),
        sealed: Some(&sealed),
    };
    let current_seen = Seen::parse(seq, str_of(current, "link")).unwrap();

    for c in m["checks"].as_array().unwrap() {
        let (k, e) = key_of(c);
        assert_eq!(c["keyEpoch"], e, "{c}");
        let (seq, prev, sealed) = row_of(&m["manifests"][str_of(c, "manifest")]);
        let log: Option<Vec<LogEntry>> = serde_json::from_value(c["log"].clone()).unwrap();
        let got = manifest::verify(
            k,
            vault_id,
            e,
            Row {
                seq,
                prev: prev.as_deref(),
                sealed: sealed.as_deref(),
            },
            seen_of(&c["remembered"]).as_ref(),
            log.as_deref(),
            &rows(&c["items"]),
        )
        .unwrap();
        assert_eq!(serde_json::to_value(&got).unwrap(), c["expected"], "{c}");
    }
    for bad in m["malformed"].as_array().unwrap() {
        let items: Vec<Entry> = serde_json::from_value(bad["items"].clone()).unwrap();
        let what = &bad["deletedAt"];
        assert!(
            manifest::verify(&key, vault_id, epoch, current_row, None, None, &items).is_err(),
            "{what}"
        );
        assert!(
            manifest::start(&key, vault_id, epoch, 1, None, &items).is_err(),
            "{what}"
        );
        let one = &items[2..];
        assert!(
            manifest::advance(&key, vault_id, epoch, current_row, one, &[]).is_err(),
            "{what}"
        );
        assert!(
            manifest::advance(&key, vault_id, epoch, current_row, &[], one).is_err(),
            "{what}"
        );
    }
    for w in m["writes"].as_array().unwrap() {
        let list = |name: &str| -> Vec<Entry> { serde_json::from_value(w[name].clone()).unwrap() };
        let next = manifest::advance(
            &key,
            vault_id,
            epoch,
            current_row,
            &list("removed"),
            &list("added"),
        )
        .unwrap();
        let opened = Manifest::open(
            &key,
            vault_id,
            epoch,
            next.seq,
            &parse_link(&next.prev).unwrap(),
            &next.sealed,
        )
        .unwrap();
        assert_eq!(
            json!({ "seq": next.seq, "prev": next.prev, "live": opened.summary.live,
                    "trashed": opened.summary.trashed, "acc": hex(&opened.summary.acc) }),
            w["expected"],
            "{w}"
        );
        assert_eq!(json!(next.prev), current["link"]);
        let after = list("after");
        let check = manifest::verify(
            &key,
            vault_id,
            epoch,
            Row {
                seq: next.seq,
                prev: Some(&next.prev),
                sealed: Some(&next.sealed),
            },
            Some(&current_seen),
            None,
            &after,
        )
        .unwrap();
        assert_eq!(check.status, manifest::Status::Ok, "{w}");
        assert_eq!(check.link.as_deref(), Some(next.link.as_str()));
    }
    for a in m["accepts"].as_array().unwrap() {
        let (k, e) = key_of(a);
        assert_eq!(a["keyEpoch"], e, "{a}");
        let (seq, prev, sealed) = row_of(&m["manifests"][str_of(a, "manifest")]);
        let row = Row {
            seq,
            prev: prev.as_deref(),
            sealed: sealed.as_deref(),
        };
        let got = manifest::accept(k, vault_id, e, row, &rows(&a["items"])).unwrap();
        assert_eq!(serde_json::to_value(&got).unwrap(), a["expected"], "{a}");
    }
    for bad in m["badMemories"].as_array().unwrap() {
        let parsed = Seen::parse(bad["version"].as_u64().unwrap(), str_of(bad, "link"));
        assert!(parsed.is_err(), "{bad}");
    }
    assert!(m["badMemories"].as_array().unwrap().len() >= 6);
    for s in m["starts"].as_array().unwrap() {
        let (k, e) = key_of(s);
        assert_eq!(s["keyEpoch"], e, "{s}");
        let items = rows(&s["items"]);
        let w = manifest::start(
            k,
            vault_id,
            e,
            s["version"].as_u64().unwrap(),
            s["prev"].as_str(),
            &items,
        )
        .unwrap();
        assert_eq!(
            json!({ "seq": w.seq, "prev": w.prev }),
            s["expected"],
            "{s}"
        );
        let check = manifest::verify(
            k,
            vault_id,
            e,
            Row {
                seq: w.seq,
                prev: Some(&w.prev),
                sealed: Some(&w.sealed),
            },
            seen_of(&s["remembered"]).as_ref(),
            None,
            &items,
        )
        .unwrap();
        assert_eq!(check.status, manifest::Status::Ok, "{s}");
    }
}
