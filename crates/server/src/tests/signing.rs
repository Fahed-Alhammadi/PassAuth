//! Signed sharing: signing identities (set once, checked), key pins (compare-and-swap),
//! signed invitations and members with their rosters (what `/sync`, invitations and
//! member lists return, and what apps verify from it), signatures and rosters the
//! server refuses, signed key replacements, re-signing a vault from before, and a
//! signed vault refusing unsigned changes.

/// A share keeps its signer's identity as it was: it still verifies once the signer's
/// account is deleted (`signer_deleted`), and a later identity change can't touch it.
#[tokio::test]
async fn a_deleted_signers_share_still_verifies() {
    let app = app().await;
    let a = user(&app, "del-a@example.com").await;
    let b = user(&app, "del-b@example.com").await;
    let c = user(&app, "del-c@example.com").await;
    let alice = identity(&app, &a).await;
    let bob = identity(&app, &b).await;
    let carol = identity(&app, &c).await;
    let v1 = [
        input(&alice.public(), "owner"),
        input(&bob.public(), "admin"),
    ];
    assert_eq!(
        signed_add(&app, &a, &alice, &bob.public(), "admin", 1, &v1)
            .await
            .0,
        StatusCode::OK
    );
    accept(&app, &b.t, &a.c.vault_id).await;
    // Bob (admin) invites Carol.
    let row = vault_in(&synced(&app, &b.t).await, &a.c.vault_id)
        .unwrap()
        .clone();
    let key =
        b.c.unlocked
            .open_shared_vault_key(&a.c.vault_id, row["wrapped_key"].as_str().unwrap())
            .unwrap();
    let share = bob
        .seal_and_sign_share(&key, &a.c.vault_id, &carol.public(), "read", 0)
        .unwrap();
    let v2 = [
        input(&alice.public(), "owner"),
        input(&bob.public(), "admin"),
        input(&carol.public(), "read"),
    ];
    let roster = bob
        .sign_roster_unchecked(&key, &a.c.vault_id, 2, 0, &v2)
        .unwrap();
    ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/members", a.c.vault_id),
        &b.t,
        json!({ "user_id": c.id, "role": "read", "sealed_key": share.sealed_key, "signature": share.signature,
                "key_epoch": 0, "roster": roster.to_json().unwrap() }),
    )
    .await;
    accept(&app, &c.t, &a.c.vault_id).await;
    let before = vault_in(&synced(&app, &c.t).await, &a.c.vault_id).unwrap()["share"].clone();
    assert_eq!(before["signer_deleted"], false);
    assert_eq!(before["signer"]["email"], "del-b@example.com");

    // Bob deletes his account.
    let reauth = reauth_token(&app, "del-b@example.com", "pw-signing-1", &b.t).await;
    let (s, v) = call_with(
        &app,
        Method::DELETE,
        "/api/account",
        Some(&b.t),
        &[("x-reauth-token", reauth.as_str())],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let after = vault_in(&synced(&app, &c.t).await, &a.c.vault_id)
        .unwrap()
        .clone();
    assert_eq!(after["share"]["signer_deleted"], true);
    assert_eq!(after["share"]["signer"], before["signer"]);
    let signer: PublicIdentity = serde_json::from_value(after["share"]["signer"].clone()).unwrap();
    assert_eq!(signer, bob.public());
    verify_share(
        &a.c.vault_id,
        &carol.public(),
        "read",
        0,
        after["wrapped_key"].as_str().unwrap(),
        &signer,
        after["share"]["signature"].as_str().unwrap(),
    )
    .unwrap();
    // The members list shows the same.
    let list = ok(
        &app,
        Method::GET,
        &format!("/api/vaults/{}/members", a.c.vault_id),
        &c.t,
        json!(null),
    )
    .await;
    let carol_row = list["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["user_id"] == c.id)
        .unwrap();
    assert_eq!(carol_row["share"], after["share"]);
}

#[tokio::test]
async fn signed_key_replacements_send_item_revisions() {
    let app = app().await;
    let a = user(&app, "rev-a@example.com").await;
    let alice = identity(&app, &a).await;
    let vault = (a.c.vault_id.as_str(), &a.c.vault_key);
    let (item, body) = new_item(vault, "one");
    let created = ok(&app, Method::POST, "/api/items", &a.t, body).await;
    let revision = created["revision"].as_i64().unwrap();
    let (new_key, wrapped) = a.c.unlocked.new_vault_key(&a.c.vault_id).unwrap();
    let roster = alice
        .sign_roster_unchecked(
            &new_key,
            &a.c.vault_id,
            1,
            1,
            &[input(&alice.public(), "owner")],
        )
        .unwrap()
        .to_json()
        .unwrap();
    let path = format!("/api/vaults/{}/rotate", a.c.vault_id);
    let rotate = |revision: Option<i64>| {
        let mut item = item_body(&item, (&a.c.vault_id, &new_key), "one");
        if let Some(r) = revision {
            item["revision"] = r.into();
        }
        call(
            &app,
            Method::POST,
            &path,
            Some(&a.t),
            json!({ "keys": [{ "user_id": a.id, "wrapped_key": wrapped, "key_kind": "account" }],
                    "items": [item], "key_epoch": 0, "roster": roster }),
        )
    };
    assert_eq!(rotate(None).await.0, StatusCode::BAD_REQUEST);
    let (s, v) = rotate(Some(revision - 1)).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("revision_conflict"))
    );
    let (s, v) = rotate(Some(revision)).await;
    assert_eq!(
        (s, &v["member_roster_seq"]),
        (StatusCode::OK, &json!(1)),
        "{v}"
    );
}

use passauth_core::sharing::{
    PublicIdentity, RosterHead, RosterMemberInput, SignedRoster, SigningIdentity, roster_head,
    verify_roster_chain, verify_share,
};

use super::*;

/// A user for these tests: the client, a token and the user id.
struct User {
    c: Client,
    t: String,
    id: String,
}

async fn user(app: &Router, email: &str) -> User {
    let c = register(app, email, "pw-signing-1").await;
    let t = token(app, email, "pw-signing-1").await;
    let id = c.unlocked.account_id.clone();
    User { c, t, id }
}

/// Make and upload `u`'s signing identity.
async fn identity(app: &Router, u: &User) -> SigningIdentity {
    let new = u.c.unlocked.new_signing_identity().unwrap();
    let v = ok(
        app,
        Method::PUT,
        "/api/account/identity",
        &u.t,
        serde_json::to_value(&new.record).unwrap(),
    )
    .await;
    assert_eq!(v["created"], true, "{v}");
    new.identity
}

/// `email`'s public identity as `/users/lookup` gives it.
async fn lookup(app: &Router, token: &str, email: &str) -> PublicIdentity {
    let v = ok(
        app,
        Method::GET,
        &format!("/api/users/lookup?email={email}"),
        token,
        json!(null),
    )
    .await;
    serde_json::from_value(v).unwrap()
}

fn input(p: &PublicIdentity, role: &str) -> RosterMemberInput {
    RosterMemberInput {
        identity: p.clone(),
        role: role.into(),
        email: None,
    }
}

/// Share `owner`'s vault with `to` (public identity) signed by `signer`, with roster
/// version `version` listing `members`.
#[allow(clippy::too_many_arguments)]
async fn signed_add(
    app: &Router,
    owner: &User,
    signer: &SigningIdentity,
    to: &PublicIdentity,
    role: &str,
    version: u64,
    members: &[RosterMemberInput],
) -> (StatusCode, Value) {
    let share = signer
        .seal_and_sign_share(&owner.c.vault_key, &owner.c.vault_id, to, role, 0)
        .unwrap();
    let roster = signer
        .sign_roster_unchecked(&owner.c.vault_key, &owner.c.vault_id, version, 0, members)
        .unwrap();
    call(
        app,
        Method::POST,
        &format!("/api/vaults/{}/members", owner.c.vault_id),
        Some(&owner.t),
        json!({
            "user_id": to.user_id, "role": role, "sealed_key": share.sealed_key,
            "signature": share.signature, "key_epoch": 0, "roster": roster.to_json().unwrap(),
        }),
    )
    .await
}

#[tokio::test]
async fn signing_identities_are_checked_and_set_once() {
    let app = app().await;
    let a = user(&app, "id-a@example.com").await;
    let b = user(&app, "id-b@example.com").await;
    let synced0 = synced(&app, &a.t).await;
    assert_eq!(synced0["user"]["identity"], Value::Null);
    assert_eq!(
        lookup(&app, &b.t, "id-a@example.com").await.signing_key,
        None
    );

    let mine = a.c.unlocked.new_signing_identity().unwrap();
    let theirs = b.c.unlocked.new_signing_identity().unwrap();
    let put = |body: Value| call(&app, Method::PUT, "/api/account/identity", Some(&a.t), body);
    // Bob's identity statement doesn't verify for Alice's account.
    let (s, v) = put(serde_json::to_value(&theirs.record).unwrap()).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_signature"))
    );
    let (s, v) =
        put(json!({ "signing_key": "x", "identity_signature": "y", "x25519_signature": "w", "wrapped_signing_key": "z" }))
            .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_request"))
    );
    // A signing key attached to Alice's X25519 key without her X25519 key's
    // cross-signature (here: another one of hers, over another statement) is refused.
    let mut forged = mine.record.clone();
    forged.x25519_signature =
        a.c.unlocked
            .new_signing_identity()
            .unwrap()
            .record
            .x25519_signature;
    let (s, v) = put(serde_json::to_value(&forged).unwrap()).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_signature"))
    );
    let (s, v) = put(serde_json::to_value(&mine.record).unwrap()).await;
    assert_eq!((s, &v["created"]), (StatusCode::OK, &json!(true)), "{v}");
    // The same again is fine; another one is refused.
    let (s, v) = put(serde_json::to_value(&mine.record).unwrap()).await;
    assert_eq!((s, &v["created"]), (StatusCode::OK, &json!(false)));
    let other = a.c.unlocked.new_signing_identity().unwrap();
    let (s, v) = put(serde_json::to_value(&other.record).unwrap()).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("identity_exists"))
    );

    // `/sync` returns the record, which opens to the same identity; others see it.
    let record = synced(&app, &a.t).await["user"]["identity"].clone();
    let opened =
        a.c.unlocked
            .open_signing_identity(&serde_json::from_value(record).unwrap())
            .unwrap();
    assert_eq!(opened.public(), mine.identity.public());
    let seen = lookup(&app, &b.t, "id-a@example.com").await;
    assert_eq!(seen, mine.identity.public());
    seen.verify().unwrap();
    let events = ok(&app, Method::GET, "/api/account/events", &a.t, json!(null)).await;
    assert!(
        events["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "account.identity_created"),
        "{events}"
    );
}

#[tokio::test]
async fn key_pins_are_stored_by_compare_and_swap() {
    let app = app().await;
    let a = user(&app, "pins-a@example.com").await;
    let b = user(&app, "pins-b@example.com").await;
    let v = ok(
        &app,
        Method::GET,
        "/api/account/key-pins",
        &a.t,
        json!(null),
    )
    .await;
    assert_eq!(v, json!({ "key_pins": null, "seq": 0 }));

    let pins = passauth_core::sharing::KeyPins::default()
        .set(
            &b.c.unlocked.legacy_identity(),
            "pins-b@example.com",
            false,
            1,
        )
        .unwrap();
    let sealed = a.c.unlocked.seal_key_pins(&pins, 1).unwrap();
    let put = |body: Value| call(&app, Method::PUT, "/api/account/key-pins", Some(&a.t), body);
    let before = rev_of(&app, &a.t).await;
    assert_eq!(
        put(json!({ "key_pins": sealed, "seq": 1 })).await.1,
        json!({ "seq": 1 })
    );
    assert!(rev_of(&app, &a.t).await > before, "other devices sync");
    for seq in [1, 3, 0] {
        let (s, v) = put(json!({ "key_pins": sealed, "seq": seq })).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::CONFLICT, Some("key_pins_changed")),
            "{seq}"
        );
    }
    let (s, _) = put(json!({ "key_pins": "not base64!", "seq": 2 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = put(json!({ "key_pins": "A".repeat(256 * 1024 + 4), "seq": 2 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    assert_eq!(synced(&app, &a.t).await["user"]["key_pins_seq"], 1);
    let v = ok(
        &app,
        Method::GET,
        "/api/account/key-pins",
        &a.t,
        json!(null),
    )
    .await;
    let opened =
        a.c.unlocked
            .open_key_pins(v["key_pins"].as_str().unwrap(), v["seq"].as_u64().unwrap())
            .unwrap();
    assert_eq!(opened.pins, pins.pins);
    // Another account can't open them, nor see them.
    assert!(b.c.unlocked.open_key_pins(&sealed, 1).is_err());
    let v = ok(
        &app,
        Method::GET,
        "/api/account/key-pins",
        &b.t,
        json!(null),
    )
    .await;
    assert_eq!(v["key_pins"], Value::Null);
}

#[tokio::test]
async fn signed_invitations_carry_what_apps_verify() {
    let app = app().await;
    let a = user(&app, "si-a@example.com").await;
    let b = user(&app, "si-b@example.com").await;
    let alice = identity(&app, &a).await;
    let bob = identity(&app, &b).await;
    let bob_pub = lookup(&app, &a.t, "si-b@example.com").await;
    assert_eq!(bob_pub, bob.public());
    let members = [input(&alice.public(), "owner"), input(&bob_pub, "write")];
    let (s, v) = signed_add(&app, &a, &alice, &bob_pub, "write", 1, &members).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["status"], &v["member_roster_seq"]),
        (&json!("invited"), &json!(1))
    );

    // Bob's invitation: the share, its signer and the roster, all checkable.
    let sync = synced(&app, &b.t).await;
    let inv = &sync["invitations"][0];
    assert_eq!(inv["key_epoch"], 0);
    assert_eq!(inv["member_roster_seq"], 1);
    assert_eq!(
        inv["invited_by"]["signing_key"],
        json!(alice.public().signing_key)
    );
    let signer: PublicIdentity = serde_json::from_value(inv["share"]["signer"].clone()).unwrap();
    assert_eq!(signer, alice.public());
    assert_eq!(inv["share"]["signer"]["email"], "si-a@example.com");
    let verified = verify_share(
        &a.c.vault_id,
        &bob.public(),
        inv["role"].as_str().unwrap(),
        0,
        inv["wrapped_key"].as_str().unwrap(),
        &signer,
        inv["share"]["signature"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(verified.fingerprint(), alice.fingerprint());
    let latest = SignedRoster::parse(inv["member_roster"].as_str().unwrap()).unwrap();
    assert_eq!(
        roster_head(&a.c.vault_id, None, Some(&latest)).unwrap(),
        RosterHead::Fetch { after: 0 }
    );
    let chain = ok(
        &app,
        Method::GET,
        &format!("/api/vaults/{}/rosters?after=0", a.c.vault_id),
        &b.t,
        json!(null),
    )
    .await;
    assert_eq!(
        (&chain["latest"], &chain["more"]),
        (&json!(1), &json!(false))
    );
    let chain: Vec<SignedRoster> = chain["rosters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| SignedRoster::parse(r.as_str().unwrap()).unwrap())
        .collect();
    let trusted = verify_roster_chain(&a.c.vault_id, None, &chain, &latest).unwrap();
    assert_eq!(trusted, latest);
    assert_eq!(
        trusted.signer_role(&alice.public()).unwrap().as_deref(),
        Some("owner")
    );
    let key =
        b.c.unlocked
            .open_shared_vault_key(&a.c.vault_id, inv["wrapped_key"].as_str().unwrap())
            .unwrap();
    assert!(trusted.commits_to(&a.c.vault_id, &key).unwrap());

    // Accepted: the vault row carries the same; the members list too.
    accept(&app, &b.t, &a.c.vault_id).await;
    let row = vault_in(&synced(&app, &b.t).await, &a.c.vault_id)
        .unwrap()
        .clone();
    assert_eq!(row["share"]["signature"], inv["share"]["signature"]);
    assert_eq!(row["member_roster"], inv["member_roster"]);
    let own = vault_in(&synced(&app, &a.t).await, &a.c.vault_id)
        .unwrap()
        .clone();
    assert_eq!(
        (&own["share"], &own["member_roster_seq"]),
        (&Value::Null, &json!(1))
    );
    let list = ok(
        &app,
        Method::GET,
        &format!("/api/vaults/{}/members", a.c.vault_id),
        &b.t,
        json!(null),
    )
    .await;
    assert_eq!(
        (&list["key_epoch"], &list["member_roster_seq"]),
        (&json!(0), &json!(1))
    );
    let rows: Vec<RosterMemberInput> = serde_json::from_value(list["members"].clone()).unwrap();
    assert!(passauth_core::sharing::compare_members(&trusted, &rows).is_clean());
    let bob_row = list["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["user_id"] == b.id)
        .unwrap();
    assert_eq!(bob_row["share"]["signature"], inv["share"]["signature"]);
    assert_eq!(bob_row["key_kind"], "sealed");

    // Not for others; the event says it was signed.
    let c = user(&app, "si-c@example.com").await;
    let (s, _) = call(
        &app,
        Method::GET,
        &format!("/api/vaults/{}/rosters", a.c.vault_id),
        Some(&c.t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let events = ok(
        &app,
        Method::GET,
        &format!("/api/vaults/{}/events", a.c.vault_id),
        &a.t,
        json!(null),
    )
    .await;
    let invited = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "member.invited")
        .unwrap();
    assert_eq!(invited["data"]["signed"], true);
}

#[tokio::test]
async fn bad_signatures_and_rosters_are_refused() {
    let app = app().await;
    let a = user(&app, "bad-a@example.com").await;
    let b = user(&app, "bad-b@example.com").await;
    let c = user(&app, "bad-c@example.com").await;
    let alice = identity(&app, &a).await;
    let bob = identity(&app, &b).await;
    let bob_pub = bob.public();
    let carol_pub = c.c.unlocked.legacy_identity();
    let path = format!("/api/vaults/{}/members", a.c.vault_id);
    let add = |body: Value| call(&app, Method::POST, &path, Some(&a.t), body);
    let share = alice
        .seal_and_sign_share(&a.c.vault_key, &a.c.vault_id, &bob_pub, "write", 0)
        .unwrap();
    let roster = |version, members: &[RosterMemberInput], by: &SigningIdentity| {
        by.sign_roster_unchecked(&a.c.vault_key, &a.c.vault_id, version, 0, members)
            .unwrap()
            .to_json()
            .unwrap()
    };
    let good = [input(&alice.public(), "owner"), input(&bob_pub, "write")];
    let body = |role: &str, signature: &str, roster: String| {
        json!({ "user_id": b.id, "role": role, "sealed_key": share.sealed_key, "signature": signature,
                "key_epoch": 0, "roster": roster })
    };
    let err = |r: (StatusCode, Value)| (r.0, r.1["error"].as_str().unwrap_or_default().to_owned());

    // The signature was for "write": as "read" it doesn't verify.
    let read_roster = roster(
        1,
        &[input(&alice.public(), "owner"), input(&bob_pub, "read")],
        &alice,
    );
    assert_eq!(
        err(add(body("read", &share.signature, read_roster)).await),
        (StatusCode::BAD_REQUEST, "bad_signature".into())
    );
    // A signature and no roster, or the reverse.
    let mut v = body("write", &share.signature, roster(1, &good, &alice));
    v.as_object_mut().unwrap().remove("roster");
    assert_eq!(err(add(v).await).0, StatusCode::BAD_REQUEST);
    // The roster's version must be the next one.
    assert_eq!(
        err(add(body("write", &share.signature, roster(2, &good, &alice))).await),
        (StatusCode::CONFLICT, "member_roster_changed".into())
    );
    // It must list exactly the members after the change.
    let without_bob = roster(1, &[input(&alice.public(), "owner")], &alice);
    let (s, v) = add(body("write", &share.signature, without_bob)).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("members_changed"))
    );
    assert_eq!(v["unknown"], json!([b.id]), "{v}");
    let extra = roster(
        1,
        &[
            input(&alice.public(), "owner"),
            input(&bob_pub, "write"),
            input(&carol_pub, "read"),
        ],
        &alice,
    );
    let (s, v) = add(body("write", &share.signature, extra)).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("members_changed"))
    );
    assert_eq!(v["missing"], json!([c.id]), "{v}");
    // Signed by someone else (Bob listing himself as admin): not the caller's.
    let by_bob = roster(
        1,
        &[input(&alice.public(), "owner"), input(&bob_pub, "admin")],
        &bob,
    );
    assert_eq!(
        err(add(body("write", &share.signature, by_bob)).await),
        (StatusCode::BAD_REQUEST, "bad_signature".into())
    );
    // Garbage roster.
    assert_eq!(
        err(add(body("write", &share.signature, "{}".into())).await).0,
        StatusCode::BAD_REQUEST
    );
    // Nothing of it was stored.
    let list = ok(&app, Method::GET, &path, &a.t, json!(null)).await;
    assert_eq!(
        (
            list["members"].as_array().unwrap().len(),
            &list["member_roster_seq"]
        ),
        (1, &json!(0))
    );

    // Carol has no signing identity: she can't sign.
    let cpath = format!("/api/vaults/{}/members", c.c.vault_id);
    let (s, v) = call(
        &app,
        Method::POST,
        &cpath,
        Some(&c.t),
        json!({ "user_id": b.id, "role": "read", "sealed_key": share.sealed_key, "signature": share.signature,
                "key_epoch": 0, "roster": roster(1, &good, &alice) }),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("signing_identity_required"))
    );

    // The good one works.
    assert_eq!(
        add(body("write", &share.signature, roster(1, &good, &alice)))
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn signed_vaults_take_signed_changes_only_and_rotate_signed() {
    let app = app().await;
    let a = user(&app, "rot-a@example.com").await;
    let b = user(&app, "rot-b@example.com").await;
    let c = user(&app, "rot-c@example.com").await;
    let alice = identity(&app, &a).await;
    let bob = identity(&app, &b).await;
    let carol_pub = c.c.unlocked.legacy_identity();
    let v1 = [
        input(&alice.public(), "owner"),
        input(&bob.public(), "admin"),
    ];
    assert_eq!(
        signed_add(&app, &a, &alice, &bob.public(), "admin", 1, &v1)
            .await
            .0,
        StatusCode::OK
    );
    accept(&app, &b.t, &a.c.vault_id).await;

    // An app from before can't add Carol unsigned any more.
    let (s, v) = share(&app, &a.c, &a.t, "rot-c@example.com", "read").await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("update_required"))
    );
    // Nor replace the key unsigned.
    let rotate_path = format!("/api/vaults/{}/rotate", a.c.vault_id);
    let (new_key, wrapped) = a.c.unlocked.new_vault_key(&a.c.vault_id).unwrap();
    let plain_bob =
        passauth_core::keys::share_vault_key(&a.c.vault_id, &new_key, &bob.public().public_key)
            .unwrap();
    let (s, v) = call(
        &app,
        Method::POST,
        &rotate_path,
        Some(&a.t),
        json!({ "keys": [
            { "user_id": a.id, "wrapped_key": wrapped, "key_kind": "account" },
            { "user_id": b.id, "wrapped_key": plain_bob, "key_kind": "sealed" },
        ], "items": [], "key_epoch": 0 }),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("update_required"))
    );

    // Bob (admin) adds Carol (a legacy account), signed: version 2, signed by an admin of v1.
    let v2 = [
        input(&alice.public(), "owner"),
        input(&bob.public(), "admin"),
        input(&carol_pub, "read"),
    ];
    let bob_key =
        b.c.unlocked
            .open_shared_vault_key(
                &a.c.vault_id,
                vault_in(&synced(&app, &b.t).await, &a.c.vault_id).unwrap()["wrapped_key"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
    let share_c = bob
        .seal_and_sign_share(&bob_key, &a.c.vault_id, &carol_pub, "read", 0)
        .unwrap();
    let r2 = bob
        .sign_roster_unchecked(&bob_key, &a.c.vault_id, 2, 0, &v2)
        .unwrap();
    let v = ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/members", a.c.vault_id),
        &b.t,
        json!({ "user_id": c.id, "role": "read", "sealed_key": share_c.sealed_key, "signature": share_c.signature,
                "key_epoch": 0, "roster": r2.to_json().unwrap() }),
    )
    .await;
    assert_eq!(v["member_roster_seq"], 2);
    accept(&app, &c.t, &a.c.vault_id).await;

    // Bob (an admin) can't make Carol an admin: only the owner changes admins
    // (the roster chain's hierarchy, checked here too).
    let raise = [
        input(&alice.public(), "owner"),
        input(&bob.public(), "admin"),
        input(&carol_pub, "admin"),
    ];
    let share_raise = bob
        .seal_and_sign_share(&bob_key, &a.c.vault_id, &carol_pub, "admin", 0)
        .unwrap();
    let r_raise = bob
        .sign_roster_unchecked(&bob_key, &a.c.vault_id, 3, 0, &raise)
        .unwrap();
    let (s, v) = call(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/members", a.c.vault_id),
        Some(&b.t),
        json!({ "user_id": c.id, "role": "admin", "sealed_key": share_raise.sealed_key, "signature": share_raise.signature,
                "key_epoch": 0, "roster": r_raise.to_json().unwrap() }),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("roster_unauthorized")),
        "{v}"
    );

    // Alice replaces the key, removing Carol: signed shares at epoch 1, roster v3.
    let remaining = [
        input(&alice.public(), "owner"),
        input(&bob.public(), "admin"),
    ];
    let signed_bob = alice
        .seal_and_sign_share(&new_key, &a.c.vault_id, &bob.public(), "admin", 1)
        .unwrap();
    let r3 = alice
        .sign_roster_unchecked(&new_key, &a.c.vault_id, 3, 1, &remaining)
        .unwrap();
    let keys = json!([
        { "user_id": a.id, "wrapped_key": wrapped, "key_kind": "account" },
        { "user_id": b.id, "wrapped_key": signed_bob.sealed_key, "key_kind": "sealed", "signature": signed_bob.signature },
    ]);
    let remove = format!("/api/vaults/{}/members/{}/remove", a.c.vault_id, c.id);
    // A sealed key without its signature, or a roster at the old epoch: refused.
    let (s, _) = call(&app, Method::POST, &remove, Some(&a.t), json!({
        "keys": [keys[0].clone(), { "user_id": b.id, "wrapped_key": signed_bob.sealed_key, "key_kind": "sealed" }],
        "items": [], "key_epoch": 0, "roster": r3.to_json().unwrap() })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let old_epoch = alice
        .sign_roster_unchecked(&new_key, &a.c.vault_id, 3, 0, &remaining)
        .unwrap();
    let (s, v) = call(
        &app,
        Method::POST,
        &remove,
        Some(&a.t),
        json!({
        "keys": keys, "items": [], "key_epoch": 0, "roster": old_epoch.to_json().unwrap() }),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("members_changed"))
    );
    // A share signed for the old epoch.
    let stale = alice
        .sign_share(
            &a.c.vault_id,
            &bob.public(),
            "admin",
            0,
            &signed_bob.sealed_key,
        )
        .unwrap();
    let (s, v) = call(&app, Method::POST, &remove, Some(&a.t), json!({
        "keys": [keys[0].clone(), { "user_id": b.id, "wrapped_key": signed_bob.sealed_key, "key_kind": "sealed", "signature": stale }],
        "items": [], "key_epoch": 0, "roster": r3.to_json().unwrap() })).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("bad_signature"))
    );
    let v = ok(
        &app,
        Method::POST,
        &remove,
        &a.t,
        json!({
        "keys": keys, "items": [], "key_epoch": 0, "roster": r3.to_json().unwrap() }),
    )
    .await;
    assert_eq!(
        (&v["key_epoch"], &v["member_roster_seq"]),
        (&json!(1), &json!(3))
    );

    // Bob checks it all from his sync and the chain he fetches after the version he trusted.
    let row = vault_in(&synced(&app, &b.t).await, &a.c.vault_id)
        .unwrap()
        .clone();
    let signer: PublicIdentity = serde_json::from_value(row["share"]["signer"].clone()).unwrap();
    verify_share(
        &a.c.vault_id,
        &bob.public(),
        "admin",
        1,
        row["wrapped_key"].as_str().unwrap(),
        &signer,
        row["share"]["signature"].as_str().unwrap(),
    )
    .unwrap();
    let chain = ok(
        &app,
        Method::GET,
        &format!("/api/vaults/{}/rosters?after=1", a.c.vault_id),
        &b.t,
        json!(null),
    )
    .await;
    let chain: Vec<SignedRoster> = chain["rosters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| SignedRoster::parse(r.as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(chain.len(), 2);
    let v1_roster = alice
        .sign_roster_unchecked(&a.c.vault_key, &a.c.vault_id, 1, 0, &v1)
        .unwrap();
    let latest = SignedRoster::parse(row["member_roster"].as_str().unwrap()).unwrap();
    let trusted = verify_roster_chain(&a.c.vault_id, Some(&v1_roster), &chain, &latest).unwrap();
    assert_eq!(trusted.version, 3);
    assert_eq!(trusted, latest);
    let key =
        b.c.unlocked
            .open_shared_vault_key(&a.c.vault_id, row["wrapped_key"].as_str().unwrap())
            .unwrap();
    assert!(latest.commits_to(&a.c.vault_id, &key).unwrap());

    // Leaving stays possible unsigned (the roster then lists someone gone until the
    // next key replacement).
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{}/members/{}", a.c.vault_id, b.id),
        Some(&b.t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // An unsigned rotation is still refused; a signed one listing only Alice works.
    let (k2, w2) = a.c.unlocked.new_vault_key(&a.c.vault_id).unwrap();
    let only = alice
        .sign_roster_unchecked(&k2, &a.c.vault_id, 4, 2, &[input(&alice.public(), "owner")])
        .unwrap();
    let (s, _) = call(&app, Method::POST, &rotate_path, Some(&a.t), json!({
        "keys": [{ "user_id": a.id, "wrapped_key": w2, "key_kind": "account" }], "items": [], "key_epoch": 1 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let v = ok(&app, Method::POST, &rotate_path, &a.t, json!({
        "keys": [{ "user_id": a.id, "wrapped_key": w2, "key_kind": "account" }], "items": [], "key_epoch": 1,
        "roster": only.to_json().unwrap() })).await;
    assert_eq!(v["member_roster_seq"], 4);
}

#[tokio::test]
async fn vaults_from_before_are_resigned_in_one_step() {
    let app = app().await;
    let a = user(&app, "rs-a@example.com").await;
    let b = user(&app, "rs-b@example.com").await;
    // Shared by an app from before: no signature, no roster.
    assert_eq!(
        share(&app, &a.c, &a.t, "rs-b@example.com", "write").await.0,
        StatusCode::OK
    );
    accept(&app, &b.t, &a.c.vault_id).await;
    let row = vault_in(&synced(&app, &b.t).await, &a.c.vault_id)
        .unwrap()
        .clone();
    assert_eq!(
        (
            &row["share"],
            &row["member_roster"],
            &row["member_roster_seq"]
        ),
        (&Value::Null, &Value::Null, &json!(0))
    );

    let alice = identity(&app, &a).await;
    let bob_pub = lookup(&app, &a.t, "rs-b@example.com").await;
    let share = alice
        .seal_and_sign_share(&a.c.vault_key, &a.c.vault_id, &bob_pub, "write", 0)
        .unwrap();
    let roster = alice
        .sign_roster_unchecked(
            &a.c.vault_key,
            &a.c.vault_id,
            1,
            0,
            &[input(&alice.public(), "owner"), input(&bob_pub, "write")],
        )
        .unwrap()
        .to_json()
        .unwrap();
    let path = format!("/api/vaults/{}/resign", a.c.vault_id);
    let resign = |body: Value| call(&app, Method::POST, &path, Some(&a.t), body);
    let key =
        json!({ "user_id": b.id, "wrapped_key": share.sealed_key, "signature": share.signature });
    // Every sealed member, the current epoch, and only owners/admins.
    let (s, _) = resign(json!({ "key_epoch": 0, "keys": [], "roster": roster })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = resign(json!({ "key_epoch": 1, "keys": [key], "roster": roster })).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("vault_key_changed"))
    );
    let (s, _) = call(
        &app,
        Method::POST,
        &path,
        Some(&b.t),
        json!({ "key_epoch": 0, "keys": [key], "roster": roster }),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let before = rev_of(&app, &b.t).await;
    let v = resign(json!({ "key_epoch": 0, "keys": [key], "roster": roster })).await;
    assert_eq!(v.0, StatusCode::OK, "{}", v.1);
    assert_eq!(v.1["member_roster_seq"], 1);
    assert!(rev_of(&app, &b.t).await > before);

    let row = vault_in(&synced(&app, &b.t).await, &a.c.vault_id)
        .unwrap()
        .clone();
    let signer: PublicIdentity = serde_json::from_value(row["share"]["signer"].clone()).unwrap();
    verify_share(
        &a.c.vault_id,
        &b.c.unlocked.legacy_identity(),
        "write",
        0,
        row["wrapped_key"].as_str().unwrap(),
        &signer,
        row["share"]["signature"].as_str().unwrap(),
    )
    .unwrap();
    let opened =
        b.c.unlocked
            .open_shared_vault_key(&a.c.vault_id, row["wrapped_key"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        opened.as_bytes(),
        a.c.vault_key.as_bytes(),
        "the same key, sealed again"
    );
    // Again with the same roster version: changed meanwhile.
    let (s, v) = resign(json!({ "key_epoch": 0, "keys": [key], "roster": roster })).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("member_roster_changed"))
    );
    let events = ok(
        &app,
        Method::GET,
        &format!("/api/vaults/{}/events", a.c.vault_id),
        &a.t,
        json!(null),
    )
    .await;
    assert!(
        events["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "vault.resigned")
    );
    // Deleting the vault takes its rosters along.
    let (second, _) = new_vault(&app, &a.c, &a.t).await;
    assert!(!second.is_empty());
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{}", a.c.vault_id),
        Some(&a.t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}
