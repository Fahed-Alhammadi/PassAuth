//! Runs the shared golden vectors (testdata/vectors.json, generated from this crate's WASM build
//! by testdata/generate-vectors.mjs) against `passauth_core::site` natively: the Rust API must
//! give exactly what the WASM bindings gave, case by case (so a difference between the two
//! builds, or a vectors.json that is out of date with the code, fails here). Every client runs
//! the same file through its own bindings (extension, iOS and macOS AutoFill, Android).

use passauth_core::device_login;
use passauth_core::site::{self, PasskeyLogin, SaveCandidate, SavePlan, UrlMatch};
use serde_json::{Value, json};

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
