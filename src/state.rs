use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use libsignal_protocol_rust;

use crate::curve::{PublicKey, KeyPair};
use crate::identity_key::IdentityKey;

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

        let pre_key: std::option::Option<libsignal_protocol_rust::PublicKey> = match pre_key_public {
            Some(inner)  => Some(inner.key),
            None => None
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
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PreKeyRecord {
    pub state: libsignal_protocol_rust::PreKeyRecord,
}

#[pymethods]
impl PreKeyRecord {
    #[new]
    fn new(id: PreKeyId, key: &KeyPair) -> Self {
        let key = libsignal_protocol_rust::KeyPair::new(key.public_key.key, key.private_key.key);
        PreKeyRecord { state: libsignal_protocol_rust::PreKeyRecord::new(id, &key) }
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
    fn new(id: SignedPreKeyId, timestamp: u64, key: &KeyPair, signature: &[u8]) -> Self {
        let key = libsignal_protocol_rust::KeyPair::new(key.public_key.key, key.private_key.key);
        SignedPreKeyRecord { state: libsignal_protocol_rust::SignedPreKeyRecord::new(id, timestamp, &key, &signature) }
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<PreKeyBundle>()?;
    module.add_class::<PreKeyRecord>()?;
    module.add_class::<SignedPreKeyRecord>()?;
    Ok(())
}
