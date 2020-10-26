use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;
use libsignal_protocol_rust::{KeyPair, PublicKey, PrivateKey};

// This file defines the signal_protocol python module.

#[pyfunction]
fn generate_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut csprng = OsRng;
    let key_pair = KeyPair::generate(&mut csprng);

    Ok((key_pair.public_key.serialize().to_vec(), key_pair.private_key.serialize().to_vec()))
}

// Curve submodule

/// SignalKeyPair is a wrapper for KeyPair
///
/// Methods from libsignal-protocol-rust not implemented:
/// new (passing in keys), from_public_and_private, calculate_signature,
/// calculate_agreement
#[pyclass]
pub struct SignalKeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

#[pymethods]
impl SignalKeyPair {
    #[new]
    fn new() -> Self {
        // Currently this method generates a new key and does
        // not allow one to pass in a PublicKey or PrivateKey.
        let mut csprng = OsRng;
        let keypair = KeyPair::generate(&mut csprng);
        SignalKeyPair {
            public_key: keypair.public_key,
            private_key: keypair.private_key,
        }
    }

    #[staticmethod]
    fn generate() -> Self {
        Self::new()
    }
}

fn init_curve_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<SignalKeyPair>()?;
    Ok(())
}

/// Signal Protocol in Python
///
/// This Rust extension provides Python bindings for the Rust crate
/// libsignal-protocol-rust.
///
/// Basic usage:
///
/// >>> pub, priv = signal_protocol.generate_keypair()
///
#[pymodule]
fn signal_protocol(py: Python, module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(generate_keypair))?;

    // Curve
    let curve_submod = PyModule::new(py, "curve")?;
    init_curve_submodule(curve_submod)?;
    module.add_submodule(curve_submod)?;

    Ok(())
}
