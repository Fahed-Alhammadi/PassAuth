//! RFC 6238 TOTP code generation from `otpauth://` URIs or bare base32 secrets.

use hmac::{KeyInit, Mac, digest::block_api::EagerHash};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Totp {
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl Totp {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let mut totp = Totp {
            secret: vec![],
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        let secret = if let Some(rest) = input.strip_prefix("otpauth://totp/") {
            let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
            let mut secret = None;
            for pair in query.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                match k.to_ascii_lowercase().as_str() {
                    "secret" => secret = Some(v.to_owned()),
                    "algorithm" => {
                        totp.algorithm = match v.to_ascii_uppercase().as_str() {
                            "SHA1" => Algorithm::Sha1,
                            "SHA256" => Algorithm::Sha256,
                            "SHA512" => Algorithm::Sha512,
                            _ => return Err(Error::InvalidTotp),
                        }
                    }
                    "digits" => totp.digits = v.parse().map_err(|_| Error::InvalidTotp)?,
                    "period" => totp.period = v.parse().map_err(|_| Error::InvalidTotp)?,
                    _ => {}
                }
            }
            secret.ok_or(Error::InvalidTotp)?
        } else {
            input.to_owned()
        };
        totp.secret = decode_base32(&secret)?;
        if totp.secret.is_empty() || !(6..=10).contains(&totp.digits) || totp.period == 0 {
            return Err(Error::InvalidTotp);
        }
        Ok(totp)
    }

    pub fn generate(&self, unix_time: u64) -> String {
        let counter = (unix_time / self.period).to_be_bytes();
        let mac = match self.algorithm {
            Algorithm::Sha1 => hmac::<sha1::Sha1>(&self.secret, &counter),
            Algorithm::Sha256 => hmac::<sha2::Sha256>(&self.secret, &counter),
            Algorithm::Sha512 => hmac::<sha2::Sha512>(&self.secret, &counter),
        };
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin =
            u32::from_be_bytes(mac[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
        let code = bin % 10u32.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// Seconds left before the current code expires.
    pub fn remaining(&self, unix_time: u64) -> u64 {
        self.period - unix_time % self.period
    }
}

fn hmac<D: EagerHash>(key: &[u8], msg: &[u8]) -> Vec<u8>
where
    hmac::Hmac<D>: KeyInit + Mac,
{
    let mut mac =
        <hmac::Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn decode_base32(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    data_encoding::BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| Error::InvalidTotp)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (8 digits).
    #[test]
    fn rfc6238_vectors() {
        let cases = [
            (
                Algorithm::Sha1,
                b"12345678901234567890".to_vec(),
                "94287082",
            ),
            (
                Algorithm::Sha256,
                b"12345678901234567890123456789012".to_vec(),
                "46119246",
            ),
            (
                Algorithm::Sha512,
                b"1234567890123456789012345678901234567890123456789012345678901234".to_vec(),
                "90693936",
            ),
        ];
        for (algorithm, secret, expected) in cases {
            let t = Totp {
                secret,
                algorithm,
                digits: 8,
                period: 30,
            };
            assert_eq!(t.generate(59), expected);
        }
    }

    #[test]
    fn parse_uri_and_bare() {
        let t = Totp::parse(
            "otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP&issuer=Ex&digits=8&algorithm=SHA256",
        )
        .unwrap();
        assert_eq!(
            (t.digits, t.algorithm, t.period),
            (8, Algorithm::Sha256, 30)
        );
        let bare = Totp::parse("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(bare.secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(bare.generate(0).len(), 6);
        assert!(Totp::parse("not base32 !!").is_err());
    }
}
