//! OPAQUE (RFC 9807) cipher suite and client helpers.
//!
//! The server never sees the password or anything it could brute-force
//! without running the protocol. The password input is `MasterKeys::login`,
//! which is already Argon2id-stretched, so the suite's own KSF is Identity.
//! Client state between round trips is serialized, so WASM/mobile callers can
//! hold it as opaque bytes.

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse, Ristretto255,
    TripleDh, ksf::Identity,
};
use rand_core06::OsRng;

use crate::crypto::SymmetricKey;
use crate::item::{b64, unb64};
use crate::{Error, Result};

pub struct Suite;

impl opaque_ke::CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2_v10::Sha512>;
    type Ksf = Identity;
}

pub use opaque_ke;

/// First message of a round trip plus the state the client keeps until the reply.
pub struct Started {
    pub state: Vec<u8>,
    pub message: String,
}

fn proto<E>(_: E) -> Error {
    Error::Malformed("opaque protocol message")
}

pub fn register_start(login_key: &SymmetricKey) -> Result<Started> {
    let r = ClientRegistration::<Suite>::start(&mut OsRng, login_key.as_bytes()).map_err(proto)?;
    Ok(Started {
        state: r.state.serialize().to_vec(),
        message: b64(&r.message.serialize()),
    })
}

/// Returns the registration upload to send to the server.
pub fn register_finish(state: &[u8], login_key: &SymmetricKey, response: &str) -> Result<String> {
    let state = ClientRegistration::<Suite>::deserialize(state).map_err(proto)?;
    let response = RegistrationResponse::<Suite>::deserialize(&unb64(response)?).map_err(proto)?;
    let r = state
        .finish(
            &mut OsRng,
            login_key.as_bytes(),
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(proto)?;
    Ok(b64(&r.message.serialize()))
}

pub fn login_start(login_key: &SymmetricKey) -> Result<Started> {
    let r = ClientLogin::<Suite>::start(&mut OsRng, login_key.as_bytes()).map_err(proto)?;
    Ok(Started {
        state: r.state.serialize().to_vec(),
        message: b64(&r.message.serialize()),
    })
}

/// Returns the credential finalization. Fails with [`Error::Decrypt`] when
/// the password (or Secret Key) is wrong, or the server is not the one the
/// account registered with.
pub fn login_finish(state: &[u8], login_key: &SymmetricKey, response: &str) -> Result<String> {
    let state = ClientLogin::<Suite>::deserialize(state).map_err(proto)?;
    let response = CredentialResponse::<Suite>::deserialize(&unb64(response)?).map_err(proto)?;
    let r = state
        .finish(
            &mut OsRng,
            login_key.as_bytes(),
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(b64(&r.message.serialize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    };

    fn server_register(setup: &ServerSetup<Suite>, id: &[u8], login: &SymmetricKey) -> Vec<u8> {
        let start = register_start(login).unwrap();
        let req =
            RegistrationRequest::<Suite>::deserialize(&unb64(&start.message).unwrap()).unwrap();
        let resp = ServerRegistration::<Suite>::start(setup, req, id).unwrap();
        let upload = register_finish(&start.state, login, &b64(&resp.message.serialize())).unwrap();
        let upload = RegistrationUpload::<Suite>::deserialize(&unb64(&upload).unwrap()).unwrap();
        ServerRegistration::<Suite>::finish(upload)
            .serialize()
            .to_vec()
    }

    fn try_login(setup: &ServerSetup<Suite>, id: &[u8], file: &[u8], login: &SymmetricKey) -> bool {
        let file = ServerRegistration::<Suite>::deserialize(file).unwrap();
        let start = login_start(login).unwrap();
        let req = CredentialRequest::<Suite>::deserialize(&unb64(&start.message).unwrap()).unwrap();
        let s = ServerLogin::start(
            &mut OsRng,
            setup,
            Some(file),
            req,
            id,
            ServerLoginParameters::default(),
        )
        .unwrap();
        let Ok(fin) = login_finish(&start.state, login, &b64(&s.message.serialize())) else {
            return false;
        };
        let fin = CredentialFinalization::<Suite>::deserialize(&unb64(&fin).unwrap()).unwrap();
        s.state
            .finish(fin, ServerLoginParameters::default())
            .is_ok()
    }

    #[test]
    fn register_and_login() {
        let setup = ServerSetup::<Suite>::new(&mut OsRng);
        let good = SymmetricKey::from_bytes([1; 32]);
        let bad = SymmetricKey::from_bytes([2; 32]);
        let file = server_register(&setup, b"acct-1", &good);
        assert!(try_login(&setup, b"acct-1", &file, &good));
        assert!(!try_login(&setup, b"acct-1", &file, &bad));
    }
}
