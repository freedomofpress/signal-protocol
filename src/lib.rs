use pyo3::prelude::*;

mod address;
mod curve;
mod error;
mod fingerprint;
mod group_cipher;
mod identity_key;
mod protocol;
mod ratchet;
mod sealed_sender;
mod sender_keys;
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
/// We do not expose a Python submodule for HKDF (a module in the upstream crate).
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

    let fingerprint_submod = PyModule::new(py, "fingerprint")?;
    fingerprint::init_submodule(fingerprint_submod)?;
    module.add_submodule(fingerprint_submod)?;

    let group_cipher_submod = PyModule::new(py, "group_cipher")?;
    group_cipher::init_submodule(group_cipher_submod)?;
    module.add_submodule(group_cipher_submod)?;

    let identity_key_submod = PyModule::new(py, "identity_key")?;
    identity_key::init_submodule(identity_key_submod)?;
    module.add_submodule(identity_key_submod)?;

    let protocol_submod = PyModule::new(py, "protocol")?;
    protocol::init_submodule(protocol_submod)?;
    module.add_submodule(protocol_submod)?;

    let ratchet_submod = PyModule::new(py, "ratchet")?;
    ratchet::init_submodule(ratchet_submod)?;
    module.add_submodule(ratchet_submod)?;

    let sealed_sender_submod = PyModule::new(py, "sealed_sender")?;
    sealed_sender::init_submodule(sealed_sender_submod)?;
    module.add_submodule(sealed_sender_submod)?;

    let sender_keys_submod = PyModule::new(py, "sender_keys")?;
    sender_keys::init_submodule(sender_keys_submod)?;
    module.add_submodule(sender_keys_submod)?;

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

    // Workaround to enable imports from submodules. Upstream issue: pyo3 issue #759
    // https://github.com/PyO3/pyo3/issues/759#issuecomment-653964601
    let mods = [
        "address",
        "curve",
        "error",
        "fingerprint",
        "group_cipher",
        "identity_key",
        "protocol",
        "ratchet",
        "sealed_sender",
        "sender_keys",
        "session_cipher",
        "session",
        "state",
        "storage",
    ];
    for module_name in mods.iter() {
        let cmd = format!(
            "import sys; sys.modules['signal_protocol.{}'] = {}",
            module_name, module_name
        );
        py.run(&cmd, None, Some(module.dict()))?;
    }
    Ok(())
}
