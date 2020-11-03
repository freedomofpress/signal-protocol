use std::convert::TryFrom;

use pyo3::prelude::*;
use pyo3::pyclass::PyClassAlloc;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

use crate::curve::{PrivateKey, PublicKey};

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
        Ok(Self {
            key: libsignal_protocol_rust::IdentityKey::try_from(public_key).unwrap(),
        })
    }

    pub fn public_key(&self, py: Python) -> PyResult<PublicKey> {
        let public_key = PublicKey::deserialize(&self.key.public_key().serialize()).unwrap();
        Ok(public_key)
    }

    pub fn serialize(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.serialize()).into())
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
        Ok(Self {
            key: libsignal_protocol_rust::IdentityKeyPair::try_from(identity_key_pair_bytes)
                .unwrap(),
        })
    }

    #[staticmethod]
    pub fn generate() -> PyResult<Self> {
        let mut csprng = OsRng;
        let key_pair = libsignal_protocol_rust::IdentityKeyPair::generate(&mut csprng);
        Ok(IdentityKeyPair { key: key_pair })
    }

    pub fn identity_key(&self, py: Python) -> PyResult<IdentityKey> {
        let identity_key = IdentityKey::new(&self.key.public_key().serialize()).unwrap();
        Ok(identity_key)
    }

    pub fn public_key(&self, py: Python) -> PyResult<PublicKey> {
        let public_key = PublicKey::deserialize(&self.key.public_key().serialize()).unwrap();
        Ok(public_key)
    }

    pub fn private_key(&self, py: Python) -> PyResult<PrivateKey> {
        let private_key = PrivateKey::deserialize(&self.key.private_key().serialize()).unwrap();
        Ok(private_key)
    }

    // Redundant? maybe remove
    pub fn serialize_private_key(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.private_key().serialize()).into())
    }

    // Redundant? maybe remove
    pub fn serialize_public_key(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.public_key().serialize()).into())
    }

    pub fn serialize(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.serialize()).into())
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<IdentityKey>()?;
    module.add_class::<IdentityKeyPair>()?;
    Ok(())
}
