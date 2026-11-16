//! Embeds the rules of the Public Suffix List (`src/site/public_suffix_list.dat`, the
//! upstream file kept byte for byte) without its comments, which are more than half of it.

use std::{env, fs, path::PathBuf};

const LIST: &str = "src/site/public_suffix_list.dat";

fn main() {
    println!("cargo::rerun-if-changed={LIST}");
    let text = fs::read_to_string(LIST).expect("read the public suffix list");
    let mut rules = String::with_capacity(text.len() / 2);
    for line in text.lines() {
        // The list's format: a rule is read up to the first whitespace; `//` starts a comment line.
        let Some(rule) = line.split_whitespace().next() else {
            continue;
        };
        if rule.starts_with("//") {
            continue;
        }
        rules.push_str(rule);
        rules.push('\n');
    }
    let out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("public_suffix_rules.txt");
    fs::write(out, rules).expect("write the public suffix rules");
}
