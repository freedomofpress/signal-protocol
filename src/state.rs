use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use libsignal_protocol_rust;

use crate::curve::{KeyPair, PublicKey};
use crate::identity_key::IdentityKey;

use crate::error::SignalProtocolError;

// Newtypes from upstream crate not exposed as part of the public API
pub type SignedPreKeyId = u32;
pub type PreKeyId = u32;

#[pyclass]
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    pub state: libsignal_protocol_rust::PreKeyBundle,
}

#[pymethods]
impl PreKeyBundle {
    #[new]
    fn new(
        registration_id: u32,
        device_id: u32,
        pre_key_id: Option<PreKeyId>,
        pre_key_public: Option<PublicKey>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: Vec<u8>,
        identity_key: IdentityKey,
    ) -> PyResult<Self> {
        let pre_key: std::option::Option<libsignal_protocol_rust::PublicKey> = match pre_key_public
        {
            Some(inner) => Some(inner.key),
            None => None,
        };

        let signed_pre_key = signed_pre_key_public.key;
        let identity_key_direct = identity_key.key;

        Ok(PreKeyBundle {
            state: libsignal_protocol_rust::PreKeyBundle::new(
                registration_id,
                device_id,
                pre_key_id,
                pre_key,
                signed_pre_key_id,
                signed_pre_key,
                signed_pre_key_signature,
                identity_key_direct,
            )
            .unwrap(),
        })
    }

    fn registration_id(&self) -> PyResult<u32> {
        match self.state.registration_id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access registration ID",
            )),
        }
    }

    fn device_id(&self) -> PyResult<u32> {
        match self.state.device_id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("could not access device ID")),
        }
    }

    fn pre_key_id(&self) -> PyResult<Option<PreKeyId>> {
        match self.state.pre_key_id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("could not access prekey ID")),
        }
    }

    fn pre_key_public(&self) -> PyResult<Option<PublicKey>> {
        let key = match self.state.pre_key_public() {
            Ok(key) => key,
            Err(_e) => {
                return Err(SignalProtocolError::new_err(
                    "could not access prekey public key",
                ))
            }
        };

        match key {
            Some(key) => Ok(Some(PublicKey { key })),
            None => Ok(None),
        }
    }

    fn signed_pre_key_id(&self) -> PyResult<SignedPreKeyId> {
        match self.state.signed_pre_key_id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access signed prekey ID",
            )),
        }
    }

    fn signed_pre_key_public(&self) -> PyResult<PublicKey> {
        match self.state.signed_pre_key_public() {
            Ok(key) => Ok(PublicKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access signed prekey public key",
            )),
        }
    }

    fn signed_pre_key_signature(&self, py: Python) -> PyResult<PyObject> {
        match self.state.signed_pre_key_signature() {
            Ok(result) => Ok(PyBytes::new(py, result).into()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access signed prekey sig",
            )),
        }
    }

    fn identity_key(&self) -> PyResult<IdentityKey> {
        match self.state.identity_key() {
            Ok(key) => Ok(IdentityKey { key: *key }),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access identity key",
            )),
        }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PreKeyRecord {
    pub state: libsignal_protocol_rust::PreKeyRecord,
}

#[pymethods]
impl PreKeyRecord {
    #[new]
    fn new(id: PreKeyId, keypair: &KeyPair) -> Self {
        let key =
            libsignal_protocol_rust::KeyPair::new(keypair.key.public_key, keypair.key.private_key);
        PreKeyRecord {
            state: libsignal_protocol_rust::PreKeyRecord::new(id, &key),
        }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct SignedPreKeyRecord {
    pub state: libsignal_protocol_rust::SignedPreKeyRecord,
}

#[pymethods]
impl SignedPreKeyRecord {
    #[new]
    fn new(id: SignedPreKeyId, timestamp: u64, keypair: &KeyPair, signature: &[u8]) -> Self {
        let key =
            libsignal_protocol_rust::KeyPair::new(keypair.key.public_key, keypair.key.private_key);
        SignedPreKeyRecord {
            state: libsignal_protocol_rust::SignedPreKeyRecord::new(
                id, timestamp, &key, &signature,
            ),
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub state: libsignal_protocol_rust::SessionRecord,
}

impl SessionRecord {
    pub fn new(state: libsignal_protocol_rust::SessionState) -> Self {
        SessionRecord {
            state: libsignal_protocol_rust::SessionRecord::new(state),
        }
    }
}

/// Note: Many methods defined on SessionState are defined directly on SessionRecord
/// where it made sense instead. This is because a SessionState adapter object cannot
/// take ownership of libsignal_protocol_rust::SessionState,
/// and libsignal_protocol_rust::SessionState does not implement Copy.
/// Lifetime annotations would be required to keep a reference, which we can't do in PyO3.
#[pymethods]
impl SessionRecord {
    #[staticmethod]
    pub fn new_fresh() -> Self {
        SessionRecord {
            state: libsignal_protocol_rust::SessionRecord::new_fresh(),
        }
    }

    // TODO: Extract useful err info from within SignalProtocolError? using its fmt::Display impl
    pub fn session_version(&self) -> PyResult<u32> {
        let session_state = self.state.session_state();

        match session_state {
            Ok(session_state) => (),
            Err(_e) => return Err(SignalProtocolError::new_err("no session found")),
        };

        match session_state.unwrap().session_version() {
            Ok(version) => Ok(version),
            Err(_e) => Err(SignalProtocolError::new_err("unknown signal error")),
        }
    }

    pub fn alice_base_key(&self, py: Python) -> PyResult<PyObject> {
        let session_state = self.state.session_state();

        match session_state {
            Ok(session_state) => (),
            Err(_e) => return Err(SignalProtocolError::new_err("no session found")),
        };

        match session_state.unwrap().alice_base_key() {
            Ok(key) => Ok(PyBytes::new(py, key).into()),
            Err(_e) => Err(SignalProtocolError::new_err("cannot get base key")),
        }
    }
}

// Not exposed: SessionState.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<PreKeyBundle>()?;
    module.add_class::<PreKeyRecord>()?;
    module.add_class::<SessionRecord>()?;
    module.add_class::<SignedPreKeyRecord>()?;
    Ok(())
}
