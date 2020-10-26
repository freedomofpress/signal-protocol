use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;
use libsignal_protocol_rust::KeyPair;

// This file defines the signal_protocol python module.

#[pyfunction]
fn generate_keypair() -> PyResult<(std::vec::Vec<u8>, std::vec::Vec<u8>)> {
    let mut csprng = OsRng;
    let key_pair = KeyPair::generate(&mut csprng);

    Ok((key_pair.public_key.serialize().to_vec(), key_pair.private_key.serialize().to_vec()))
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
///
#[pymodule]
fn signal_protocol(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(generate_keypair))?;
    Ok(())
}
