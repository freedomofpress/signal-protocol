use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

use crate::error::SignalProtocolError;

#[pyfunction]
pub fn generate_keypair(py: Python) -> PyResult<(PyObject, PyObject)> {
    let mut csprng = OsRng;
    let key_pair = libsignal_protocol_rust::KeyPair::generate(&mut csprng);

    Ok((
        PyBytes::new(py, &key_pair.public_key.serialize()).into(),
        PyBytes::new(py, &key_pair.private_key.serialize()).into(),
    ))
}

#[pyclass]
#[derive(Clone)]
pub struct KeyPair {
    pub key: libsignal_protocol_rust::KeyPair,
}

#[pymethods]
impl KeyPair {
    #[new]
    fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        let mut csprng = OsRng;
        let keypair = libsignal_protocol_rust::KeyPair::new(public_key.key, private_key.key);
        KeyPair { key: keypair }
    }

    #[staticmethod]
    fn generate() -> Self {
        let mut csprng = OsRng;
        let keypair = libsignal_protocol_rust::KeyPair::generate(&mut csprng);
        KeyPair { key: keypair }
    }

    pub fn public_key(&self, py: Python) -> PyResult<PublicKey> {
        match PublicKey::deserialize(&self.key.public_key.serialize()) {
            Ok(public_key) => Ok(public_key),
            Err(_e) => Err(SignalProtocolError::new_err("error getting PublicKey")),
        }
    }

    pub fn private_key(&self, py: Python) -> PyResult<PrivateKey> {
        match PrivateKey::deserialize(&self.key.private_key.serialize()) {
            Ok(private_key) => Ok(private_key),
            Err(_e) => Err(SignalProtocolError::new_err("error getting PrivateKey")),
        }
    }

    pub fn serialize(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.key.public_key.serialize()).into())
    }

    pub fn calculate_signature(&self, py: Python, message: &[u8]) -> PyResult<PyObject> {
        let mut csprng = OsRng;
        match self.key.calculate_signature(&message, &mut csprng) {
            Ok(result) => Ok(PyBytes::new(py, &result).into()),
            Err(_e) => Err(SignalProtocolError::new_err("error calculating signature")),
        }
    }

    pub fn calculate_agreement(&self, py: Python, their_key: &PublicKey) -> PyResult<PyObject> {
        match self.key.calculate_agreement(&their_key.key) {
            Ok(result) => Ok(PyBytes::new(py, &result).into()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not calculate keypair agreement",
            )),
        }
    }

    #[staticmethod]
    pub fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::KeyPair::from_public_and_private(public_key, private_key) {
            Ok(key) => Ok(KeyPair { key }),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not create KeyPair object",
            )),
        }
    }
}

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub struct PublicKey {
    pub key: libsignal_protocol_rust::PublicKey,
}

impl PublicKey {
    fn new(key: libsignal_protocol_rust::PublicKey) -> Self {
        PublicKey { key }
    }
}

/// key_type is not implemented for PublicKey.
#[pymethods]
impl PublicKey {
    #[staticmethod]
    pub fn deserialize(key: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::PublicKey::deserialize(key) {
            Ok(key) => Ok(Self { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not deserialize")),
        }
    }

    pub fn serialize(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.key.serialize()).into()
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> PyResult<bool> {
        match self.key.verify_signature(&message, &signature) {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("error verifying signature")),
        }
    }
}

#[pyclass]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PrivateKey {
    pub key: libsignal_protocol_rust::PrivateKey,
}

impl PrivateKey {
    fn new(key: libsignal_protocol_rust::PrivateKey) -> Self {
        PrivateKey { key }
    }
}

/// key_type() is not implemented on this struct.
#[pymethods]
impl PrivateKey {
    #[staticmethod]
    pub fn deserialize(key: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::PrivateKey::deserialize(key) {
            Ok(key) => Ok(Self { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not deserialize")),
        }
    }

    pub fn serialize(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.key.serialize()).into()
    }

    pub fn calculate_signature(&self, message: &[u8], py: Python) -> PyResult<PyObject> {
        let mut csprng = OsRng;
        match self.key.calculate_signature(message, &mut csprng) {
            Ok(sig) => Ok(PyBytes::new(py, &sig).into()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not calculate signature",
            )),
        }
    }

    pub fn calculate_agreement(&self, py: Python, their_key: &PublicKey) -> PyResult<PyObject> {
        match self.key.calculate_agreement(&their_key.key) {
            Ok(result) => Ok(PyBytes::new(py, &result).into()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not calculate agreement",
            )),
        }
    }

    pub fn public_key(&self) -> PyResult<PublicKey> {
        match self.key.public_key() {
            Ok(key) => Ok(PublicKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not get public key")),
        }
    }
}

#[pyfunction]
pub fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    match public_key.verify_signature(message, signature) {
        Ok(result) => Ok(result),
        Err(_e) => Err(SignalProtocolError::new_err("could not check signature")),
    }
}

/// KeyType is not exposed as part of the Python API.
pub fn init_curve_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<KeyPair>()?;
    module.add_class::<PublicKey>()?;
    module.add_class::<PrivateKey>()?;
    module.add_wrapped(wrap_pyfunction!(generate_keypair))?;
    module.add_wrapped(wrap_pyfunction!(verify_signature))?;
    Ok(())
}
