use pyo3::prelude::*;
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

    fn public_key(&self) -> PyResult<Vec<u8>> {
        let key_data = self.public_key.key.serialize();
        Ok(key_data.to_vec())
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

#[pyclass]
pub struct PrivateKey {
    key: libsignal_protocol_rust::PrivateKey,
}

impl PrivateKey {
    fn new(key: libsignal_protocol_rust::PrivateKey) -> Self {
        PrivateKey { key }
    }
}

pub fn init_curve_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<KeyPair>()?;
    module.add_class::<PublicKey>()?;
    module.add_class::<PrivateKey>()?;
    module.add_wrapped(wrap_pyfunction!(generate_keypair))?;
    Ok(())
}