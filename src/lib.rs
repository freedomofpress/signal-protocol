use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod address;
mod curve;
mod error;
mod identity_key;
mod protocol;
mod ratchet;
mod session;
mod session_cipher;
mod state;
mod storage;

/// Signal Protocol in Python
///
/// This Rust extension provides Python bindings for the Rust crate
/// libsignal-protocol-rust.
///
/// Basic usage:
///
/// >>> pub, priv = signal_protocol.curve.generate_keypair()
///
#[pymodule]
fn signal_protocol(py: Python, module: &PyModule) -> PyResult<()> {
    let address_submod = PyModule::new(py, "address")?;
    address::init_submodule(address_submod)?;
    module.add_submodule(address_submod)?;

    let curve_submod = PyModule::new(py, "curve")?;
    curve::init_curve_submodule(curve_submod)?;
    module.add_submodule(curve_submod)?;

    let error_submod = PyModule::new(py, "error")?;
    error::init_submodule(py, error_submod)?;
    module.add_submodule(error_submod)?;

    let identity_key_submod = PyModule::new(py, "identity_key")?;
    identity_key::init_submodule(identity_key_submod)?;
    module.add_submodule(identity_key_submod)?;

    let protocol_submod = PyModule::new(py, "protocol")?;
    protocol::init_submodule(protocol_submod)?;
    module.add_submodule(protocol_submod)?;

    let ratchet_submod = PyModule::new(py, "ratchet")?;
    ratchet::init_submodule(ratchet_submod)?;
    module.add_submodule(ratchet_submod)?;

    let session_cipher_submod = PyModule::new(py, "session_cipher")?;
    session_cipher::init_submodule(session_cipher_submod)?;
    module.add_submodule(session_cipher_submod)?;

    let session_submod = PyModule::new(py, "session")?;
    session::init_submodule(session_submod)?;
    module.add_submodule(session_submod)?;

    let state_submod = PyModule::new(py, "state")?;
    state::init_submodule(state_submod)?;
    module.add_submodule(state_submod)?;

    let storage_submod = PyModule::new(py, "storage")?;
    storage::init_submodule(storage_submod)?;
    module.add_submodule(storage_submod)?;

    Ok(())
}
