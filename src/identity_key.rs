use std::convert::TryFrom;

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::types::PyBytes;

use rand::rngs::OsRng;

use libsignal_protocol_rust;


#[pyclass]
pub struct IdentityKey {
    pub key: libsignal_protocol_rust::IdentityKey,
}

#[pymethods]
impl IdentityKey {
    // The behavior of libsignal_protocol_rust::IdentityKey::decode is provided
    // by the new() function.
    #[new]
    pub fn new(public_key: &[u8]) -> PyResult<Self> {
        Ok(Self { key: libsignal_protocol_rust::IdentityKey::try_from(public_key).unwrap() })
    }

    // There is no libsignal_protocol_rust::IdentityKey::public_key method,
    // instead one can use the serialized public key via this serialize()
    // method.
    pub fn serialize(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.serialize()).into())
    }
}

#[pyclass]
pub struct IdentityKeyPair {
    pub key: libsignal_protocol_rust::IdentityKeyPair,
}

/// ## Note on comparison with upstream crate:
///
/// There is no identity_key method exposed, but one can extract the public
/// key and private key bytes via the public_key() and public_key() methods
/// respectively, or the serialized identity key pair via serialize().
#[pymethods]
impl IdentityKeyPair {
    #[new]
    pub fn new(identity_key_pair_bytes: &[u8]) -> PyResult<Self> {
        Ok( Self{ key: libsignal_protocol_rust::IdentityKeyPair::try_from(identity_key_pair_bytes).unwrap() } )
    }

    #[staticmethod]
    pub fn generate() -> PyResult<Self> {
        let mut csprng = OsRng;
        let key_pair = libsignal_protocol_rust::IdentityKeyPair::generate(&mut csprng);
        Ok(IdentityKeyPair{key: key_pair})
    }

    pub fn public_key(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.public_key().serialize()).into())
    }

    pub fn private_key(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.private_key().serialize()).into())
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
