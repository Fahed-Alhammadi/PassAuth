//! Strength estimate for a user-chosen password, in bits.
//!
//! Character-class entropy alone rates `password123` like 11 random characters. This module
//! also looks for the shapes people actually use: a common password or a dictionary word
//! (capitalised, with look-alike digits or symbols), plus a short number or symbol before or
//! after it; a year; a run of one character; a sequence (`abcdef`, `123456`); a keyboard row
//! (`qwerty`, `asdfgh`). The estimate is the lower of the two, so it can only get stricter:
//! random passwords and generated passphrases keep their character-class value.

use crate::generator::WORDLIST;

/// Base words of the most common passwords (lower case, letters only), from public
/// breach-frequency rankings. A whole password made of one of these, give or take
/// capitals, look-alike characters and a short number or symbol, is weak.
const COMMON: &[&str] = &[
    "password",
    "passw",
    "passwd",
    "pass",
    "qwerty",
    "qwertz",
    "azerty",
    "admin",
    "administrator",
    "root",
    "user",
    "guest",
    "login",
    "welcome",
    "letmein",
    "iloveyou",
    "love",
    "lovely",
    "monkey",
    "dragon",
    "master",
    "shadow",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "soccer",
    "hockey",
    "basketball",
    "superman",
    "batman",
    "spiderman",
    "starwars",
    "pokemon",
    "michael",
    "jennifer",
    "jordan",
    "hunter",
    "ranger",
    "buster",
    "tigger",
    "charlie",
    "robert",
    "thomas",
    "daniel",
    "andrew",
    "jessica",
    "ashley",
    "michelle",
    "nicole",
    "matthew",
    "joshua",
    "william",
    "george",
    "maggie",
    "ginger",
    "pepper",
    "cookie",
    "chocolate",
    "cheese",
    "banana",
    "orange",
    "apple",
    "flower",
    "summer",
    "winter",
    "spring",
    "autumn",
    "january",
    "february",
    "march",
    "april",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    "monday",
    "friday",
    "sunday",
    "secret",
    "freedom",
    "whatever",
    "trustno",
    "access",
    "hello",
    "hellow",
    "test",
    "testing",
    "demo",
    "default",
    "changeme",
    "computer",
    "internet",
    "samsung",
    "google",
    "facebook",
    "linkedin",
    "twitter",
    "microsoft",
    "windows",
    "mustang",
    "harley",
    "ferrari",
    "porsche",
    "corvette",
    "liverpool",
    "chelsea",
    "arsenal",
    "barcelona",
    "madrid",
    "killer",
    "fuckyou",
    "asshole",
    "bailey",
    "angel",
    "angels",
    "baby",
    "babygirl",
    "family",
    "friend",
    "friends",
    "lucky",
    "happy",
    "smile",
    "london",
    "paris",
    "dubai",
    "abc",
    "abcd",
    "zxcvbn",
    "zxcvbnm",
    "asdf",
    "asdfgh",
    "asdfghjkl",
    "qazwsx",
    "qwertyuiop",
    "butterfly",
    "superstar",
    "starlight",
    "rockstar",
    "matrix",
    "phoenix",
    "hannah",
    "jasmine",
];

/// Keyboard rows (and their reverse), for runs like `qwerty` or `poiuy`.
const KEYBOARD_ROWS: &[&str] = &[
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "qazwsxedcrfvtgbyhnujmikolp",
];

/// Digit and symbol endings people add to meet a rule; each costs about 2 bits.
const COMMON_AFFIXES: &[&str] = &[
    "1", "12", "123", "1234", "12345", "123456", "01", "007", "69", "99", "11", "00", "13", "21",
    "22", "23", "!", "!!", "!!!", "1!", "123!", "@", "#", "$", "*", ".", "?", "_", "!1", "@123",
];

/// Rough strength estimate in bits for a user-chosen password.
pub fn estimate_bits(password: &str) -> f64 {
    let class_bits = class_entropy(password);
    match pattern_bits(password) {
        Some(bits) => bits.min(class_bits),
        None => class_bits,
    }
}

/// Character-class entropy: length × log2(size of the character classes used).
fn class_entropy(password: &str) -> f64 {
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

/// Bits for a password that follows a known shape, or `None` when none matches.
fn pattern_bits(password: &str) -> Option<f64> {
    if password.is_empty() {
        return None;
    }
    if let Some(bits) = simple_run_bits(password) {
        return Some(bits);
    }
    let lower = password.to_lowercase();
    if let Some(bits) = year_bits(&lower) {
        return Some(bits);
    }

    // Split into a core and digit/symbol affixes around it, then match the core with look-alikes undone.
    let chars: Vec<char> = password.chars().collect();
    let is_affix = |c: &char| !c.is_alphabetic();
    let start = chars.iter().take_while(|c| is_affix(c)).count();
    let end = chars.len()
        - chars[start..]
            .iter()
            .rev()
            .take_while(|c| is_affix(c))
            .count();
    if start >= end {
        return None; // digits and symbols only, and not a run or year: leave it to class entropy
    }
    let core: String = chars[start..end].iter().collect();
    let prefix: String = chars[..start].iter().collect();
    let suffix: String = chars[end..].iter().collect();

    let (plain, leet) = unleet(&core);
    if !plain.chars().all(|c| c.is_ascii_lowercase()) {
        return None; // spaces, separators or other letters: not a single word
    }
    let word_bits = if let Some(rank) = COMMON.iter().position(|w| *w == plain) {
        // A rank-weighted guess count, as crackers try the most common first.
        ((rank + 2) as f64).log2()
    } else if let Some(bits) = keyboard_or_sequence_bits(&plain) {
        bits
    } else if WORDLIST.lines().any(|w| w == plain) {
        (WORDLIST.lines().count() as f64).log2()
    } else {
        return None;
    };
    Some(
        word_bits
            + case_bits(&core)
            + if leet { 1.0 } else { 0.0 }
            + affix_bits(&prefix)
            + affix_bits(&suffix),
    )
}

/// One character repeated (`aaaaaa`) or a straight sequence (`abcdef`, `987654`, `qwerty` handled later).
fn simple_run_bits(password: &str) -> Option<f64> {
    let chars: Vec<char> = password.to_lowercase().chars().collect();
    if chars.len() < 3 {
        return None;
    }
    if chars.iter().all(|c| *c == chars[0]) {
        return Some(5.0 + (chars.len() as f64).log2());
    }
    keyboard_or_sequence_bits(&chars.iter().collect::<String>())
}

/// A run of 3+ characters along the alphabet, digits or a keyboard row, in either direction.
fn keyboard_or_sequence_bits(s: &str) -> Option<f64> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 3 {
        return None;
    }
    let step = chars[1] as i32 - chars[0] as i32;
    if (step == 1 || step == -1) && chars.windows(2).all(|w| w[1] as i32 - w[0] as i32 == step) {
        return Some(4.0 + (chars.len() as f64).log2());
    }
    let reversed: String = s.chars().rev().collect();
    if KEYBOARD_ROWS
        .iter()
        .any(|row| row.contains(s) || row.contains(reversed.as_str()))
    {
        return Some(6.0 + (chars.len() as f64).log2());
    }
    None
}

/// A year from 1900 to 2099, alone.
fn year_bits(s: &str) -> Option<f64> {
    let year: u32 = s.parse().ok().filter(|_| s.len() == 4)?;
    (1900..=2099).contains(&year).then_some(7.6)
}

/// Bits added by capital letters: none, the first only or all = 1 bit; any other mix = per capital.
fn case_bits(core: &str) -> f64 {
    let letters: Vec<char> = core.chars().filter(|c| c.is_alphabetic()).collect();
    let upper = letters.iter().filter(|c| c.is_uppercase()).count();
    if upper == 0 {
        0.0
    } else if upper == letters.len() || (upper == 1 && letters[0].is_uppercase()) {
        1.0
    } else {
        upper as f64 * 2.0
    }
}

/// Bits for digits or symbols before or after the core.
fn affix_bits(affix: &str) -> f64 {
    if affix.is_empty() {
        0.0
    } else if COMMON_AFFIXES.contains(&affix) {
        2.0
    } else if year_bits(affix).is_some() {
        7.6
    } else {
        class_entropy(affix)
    }
}

/// The letter a look-alike digit or symbol stands for.
fn leet_letter(c: char) -> Option<char> {
    Some(match c {
        '0' => 'o',
        '1' | '!' => 'i',
        '3' => 'e',
        '4' | '@' => 'a',
        '5' | '$' => 's',
        '7' => 't',
        '8' => 'b',
        _ => return None,
    })
}

/// Lower case with look-alikes replaced; `true` when any were.
fn unleet(core: &str) -> (String, bool) {
    let mut leet = false;
    let plain = core
        .chars()
        .map(|c| match leet_letter(c) {
            Some(l) => {
                leet = true;
                l
            }
            None => c.to_ascii_lowercase(),
        })
        .collect();
    (plain, leet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{PassphraseOptions, PasswordOptions, passphrase, password};

    const WEAK: f64 = 50.0;

    #[test]
    fn common_shapes_are_weak() {
        for p in [
            "password123",
            "Password1!",
            "P@ssw0rd!",
            "p@$$w0rd",
            "qwerty123",
            "Qwertyuiop1",
            "iloveyou",
            "Monkey1!",
            "Summer2024!",
            "letmein!!",
            "Welcome@123",
            "dragon99",
            "12345678",
            "1234567890",
            "987654321",
            "abcdefgh",
            "aaaaaaaaaaaa",
            "11111111",
            "asdfghjkl",
            "zxcvbnm123",
            "2024",
            "Admin2025",
            "Sunshine",
            "football1",
            "Butterfly2023",
            "Chocolate!",
            "Liverpool1",
        ] {
            let bits = estimate_bits(p);
            assert!(bits < WEAK, "{p} rated {bits:.1} bits");
        }
    }

    #[test]
    fn random_and_generated_stay_strong() {
        for p in [
            "Xk9#mQ2$vL7pR4&w",
            "kT4!vq9Zr2Lm",
            "correct-horse-battery-staple-7",
            "Tr0ub4dor&3xyz!",
        ] {
            let bits = estimate_bits(p);
            assert!(bits >= WEAK, "{p} rated {bits:.1} bits");
        }
        for _ in 0..50 {
            let p = password(&PasswordOptions::default()).unwrap();
            assert!(estimate_bits(&p) > 100.0, "{p}");
            let phrase = passphrase(&PassphraseOptions::default()).unwrap();
            assert!(estimate_bits(&phrase) >= 80.0, "{phrase}");
        }
    }

    #[test]
    fn never_above_class_entropy() {
        for p in [
            "",
            "a",
            "ab",
            "password",
            "Zz9!",
            "a long sentence with spaces",
        ] {
            assert!(estimate_bits(p) <= class_entropy(p));
        }
    }

    #[test]
    fn orders_strength() {
        assert!(estimate_bits("password") < estimate_bits("Tr0ub4dor&3xyz!"));
        assert!(estimate_bits("password123") < estimate_bits("pa55word-river-71"));
    }
}
