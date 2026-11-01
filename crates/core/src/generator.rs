//! Password and passphrase generation with an unbiased CSPRNG.
//!
//! Passphrases use the EFF large wordlist (7776 words, ~12.9 bits/word),
//! © Electronic Frontier Foundation, CC BY 3.0 US.

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const WORDLIST: &str = include_str!("eff_large_wordlist.txt");
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*-_=+?";
const AMBIGUOUS: &str = "Il1O0o";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 5,
            separator: "-".into(),
            capitalize: true,
            include_number: true,
        }
    }
}

/// Uniform integer in `0..n` (rejection sampling, no modulo bias).
fn below(n: u32) -> Result<u32> {
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let x = getrandom::u32().map_err(|_| Error::Rng)?;
        if x < zone {
            return Ok(x % n);
        }
    }
}

fn pick(chars: &[char]) -> Result<char> {
    Ok(chars[below(chars.len() as u32)? as usize])
}

pub fn password(opts: &PasswordOptions) -> Result<String> {
    let length = opts.length.clamp(8, 128);
    let filter = |set: &str| -> Vec<char> {
        set.chars()
            .filter(|c| !(opts.avoid_ambiguous && AMBIGUOUS.contains(*c)))
            .collect()
    };
    let classes: Vec<Vec<char>> = [
        (opts.lowercase, LOWER),
        (opts.uppercase, UPPER),
        (opts.digits, DIGITS),
        (opts.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, set)| filter(set))
    .collect();
    let classes = if classes.is_empty() {
        vec![filter(LOWER)]
    } else {
        classes
    };
    let all: Vec<char> = classes.concat();

    // One character from each selected class, the rest from the union, then shuffle.
    let mut out: Vec<char> = classes.iter().map(|c| pick(c)).collect::<Result<_>>()?;
    while out.len() < length {
        out.push(pick(&all)?);
    }
    for i in (1..out.len()).rev() {
        out.swap(i, below(i as u32 + 1)? as usize);
    }
    Ok(out.into_iter().collect())
}

pub fn passphrase(opts: &PassphraseOptions) -> Result<String> {
    let list: Vec<&str> = WORDLIST.lines().collect();
    let count = opts.words.clamp(3, 20);
    let mut words: Vec<String> = (0..count)
        .map(|_| {
            let w = list[below(list.len() as u32)? as usize];
            Ok(if opts.capitalize {
                let mut c = w.chars();
                c.next()
                    .map(|f| f.to_uppercase().chain(c).collect())
                    .unwrap_or_default()
            } else {
                w.to_owned()
            })
        })
        .collect::<Result<_>>()?;
    if opts.include_number {
        let i = below(count as u32)? as usize;
        words[i].push_str(&below(10)?.to_string());
    }
    Ok(words.join(&opts.separator))
}

/// Rough strength estimate in bits for a user-chosen password (character-class entropy).
pub fn estimate_bits(password: &str) -> f64 {
    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 33;
    }
    password.chars().count() as f64 * f64::from(pool.max(1)).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_has_every_class() {
        for _ in 0..50 {
            let p = password(&PasswordOptions::default()).unwrap();
            assert_eq!(p.len(), 20);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn ambiguous_excluded() {
        let opts = PasswordOptions {
            length: 128,
            avoid_ambiguous: true,
            ..Default::default()
        };
        let p = password(&opts).unwrap();
        assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
    }

    #[test]
    fn passphrase_shape() {
        assert_eq!(WORDLIST.lines().count(), 7776);
        let p = passphrase(&PassphraseOptions::default()).unwrap();
        assert_eq!(p.split('-').count(), 5);
        assert!(p.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn estimate_orders_strength() {
        assert!(estimate_bits("password") < estimate_bits("Tr0ub4dor&3xyz!"));
    }
}
