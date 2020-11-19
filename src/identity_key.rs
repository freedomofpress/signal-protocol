use std::convert::TryFrom;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use rand::rngs::OsRng;

use crate::curve::{PrivateKey, PublicKey};
use crate::error::SignalProtocolError;

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub struct IdentityKey {
    pub key: libsignal_protocol_rust::IdentityKey,
}

#[pymethods]
impl IdentityKey {
    // The behavior of libsignal_protocol_rust::IdentityKey::decode is provided
    // by the new() function.
    #[new]
    pub fn new(public_key: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::IdentityKey::try_from(public_key) {
            Ok(key) => Ok(Self { key }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn public_key(&self) -> Result<PublicKey, SignalProtocolError> {
        Ok(PublicKey::deserialize(&self.key.public_key().serialize())?)
    }

    pub fn serialize(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.key.serialize()).into()
    }
}

#[pyclass]
#[derive(Clone, Copy)]
pub struct IdentityKeyPair {
    pub key: libsignal_protocol_rust::IdentityKeyPair,
}

#[pymethods]
impl IdentityKeyPair {
    #[new]
    pub fn new(identity_key_pair_bytes: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::IdentityKeyPair::try_from(identity_key_pair_bytes) {
            Ok(key) => Ok(Self { key }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    #[staticmethod]
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let key_pair = libsignal_protocol_rust::IdentityKeyPair::generate(&mut csprng);
        IdentityKeyPair { key: key_pair }
    }

    pub fn identity_key(&self) -> PyResult<IdentityKey> {
        match IdentityKey::new(&self.key.public_key().serialize()) {
            Ok(key) => Ok(key),
            Err(err) => Err(err),
        }
    }

    pub fn public_key(&self) -> Result<PublicKey, SignalProtocolError> {
        Ok(PublicKey::deserialize(&self.key.public_key().serialize())?)
    }

    pub fn private_key(&self) -> Result<PrivateKey, SignalProtocolError> {
        Ok(PrivateKey::deserialize(
            &self.key.private_key().serialize(),
        )?)
    }

    pub fn serialize(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.key.serialize()).into()
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<IdentityKey>()?;
    module.add_class::<IdentityKeyPair>()?;
    Ok(())
}
