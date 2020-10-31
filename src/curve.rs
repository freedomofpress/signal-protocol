use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

#[pyfunction]
pub fn generate_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut csprng = OsRng;
    let key_pair = libsignal_protocol_rust::KeyPair::generate(&mut csprng);

    Ok((key_pair.public_key.serialize().to_vec(), key_pair.private_key.serialize().to_vec()))
}

/// SignalKeyPair is a wrapper for KeyPair
///
/// Methods from libsignal-protocol-rust not implemented:
/// new (passing in keys), from_public_and_private, calculate_signature,
/// calculate_agreement
#[pyclass]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

#[pymethods]
impl KeyPair {
    #[new]
    fn new() -> Self {
        // Currently this method generates a new key and does
        // not allow one to pass in a PublicKey or PrivateKey.
        let mut csprng = OsRng;
        let keypair = libsignal_protocol_rust::KeyPair::generate(&mut csprng);
        KeyPair {
            public_key: PublicKey{ key: keypair.public_key } ,
            private_key: PrivateKey{ key: keypair.private_key },
        }
    }

    #[staticmethod]
    fn generate() -> Self {
        Self::new()
    }

    pub fn public_key(&self, py: Python) -> PyResult<PublicKey> {
        let public_key = PublicKey::deserialize(&self.public_key.key.serialize()).unwrap();
        Ok(public_key)
    }

    pub fn serialize(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.public_key.key.serialize()).into())
    }
}

#[pyclass]
pub struct PublicKey {
    key: libsignal_protocol_rust::PublicKey,
}

impl PublicKey {
    fn new(key: libsignal_protocol_rust::PublicKey) -> Self {
        PublicKey { key }
    }
}

#[pymethods]
impl PublicKey {
    #[staticmethod]
    pub fn deserialize(key: &[u8]) -> PyResult<Self> {
        Ok(Self{ key: libsignal_protocol_rust::PublicKey::deserialize(key).unwrap() })
    }

    pub fn serialize(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.serialize()).into())
    }
}

#[pyclass]
pub struct PrivateKey {
    key: libsignal_protocol_rust::PrivateKey,
}

impl PrivateKey {
    fn new(key: libsignal_protocol_rust::PrivateKey) -> Self {
        PrivateKey { key }
    }
}

#[pymethods]
impl PrivateKey {
    #[staticmethod]
    pub fn deserialize(key: &[u8]) -> PyResult<Self> {
        Ok(Self{ key: libsignal_protocol_rust::PrivateKey::deserialize(key).unwrap() })
    }

    pub fn calculate_signature(&self, message: &[u8], py: Python) -> PyResult<PyObject> {
        let mut csprng = OsRng;
        let sig = self.key.calculate_signature(message, &mut csprng).unwrap();
        Ok(PyBytes::new(py, &sig).into())
    }
}

pub fn init_curve_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<KeyPair>()?;
    module.add_class::<PublicKey>()?;
    module.add_class::<PrivateKey>()?;
    module.add_wrapped(wrap_pyfunction!(generate_keypair))?;
    Ok(())
}