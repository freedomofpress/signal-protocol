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
    #[new]
    pub fn new(public_key: &[u8]) -> Self {
        Self { key: libsignal_protocol_rust::IdentityKey::try_from(public_key).unwrap() }
    }

    pub fn serialize(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.serialize()).into())
    }
}

#[pyclass]
pub struct IdentityKeyPair {
    pub key: libsignal_protocol_rust::IdentityKeyPair,
}

#[pymethods]
impl IdentityKeyPair {
    #[staticmethod]
    pub fn generate() -> PyResult<Self> {
        let mut csprng = OsRng;
        let key_pair = libsignal_protocol_rust::IdentityKeyPair::generate(&mut csprng);
        Ok(IdentityKeyPair{key: key_pair})
    }

    pub fn public_key(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.public_key().serialize()).into())
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<IdentityKey>()?;
    module.add_class::<IdentityKeyPair>()?;
    Ok(())
}
