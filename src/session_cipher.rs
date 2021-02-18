use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use futures::executor::block_on;
use rand::rngs::OsRng;

use crate::address::ProtocolAddress;
use crate::error::SignalProtocolError;
use crate::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn message_encrypt(
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &[u8],
) -> Result<CiphertextMessage, SignalProtocolError> {
    let ciphertext = block_on(libsignal_protocol_rust::message_encrypt(
        msg,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        None,
    ))?;
    Ok(CiphertextMessage::new(ciphertext))
}

#[pyfunction]
pub fn message_decrypt(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &CiphertextMessage,
) -> Result<PyObject, SignalProtocolError> {
    let mut csprng = OsRng;
    let plaintext = block_on(libsignal_protocol_rust::message_decrypt(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        &mut csprng,
        None,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn message_decrypt_prekey(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &PreKeySignalMessage,
) -> Result<PyObject, SignalProtocolError> {
    let mut csprng = OsRng;
    let plaintext = block_on(libsignal_protocol_rust::message_decrypt_prekey(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        &mut csprng,
        None,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn message_decrypt_signal(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &SignalMessage,
) -> Result<PyObject, SignalProtocolError> {
    let mut csprng = OsRng;
    let plaintext = block_on(libsignal_protocol_rust::message_decrypt_signal(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut csprng,
        None,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn remote_registration_id(
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
) -> Result<u32, SignalProtocolError> {
    Ok(block_on(libsignal_protocol_rust::remote_registration_id(
        &remote_address.state,
        &mut protocol_store.store.session_store,
        None,
    ))?)
}

#[pyfunction]
pub fn session_version(
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
) -> Result<u32, SignalProtocolError> {
    Ok(block_on(libsignal_protocol_rust::session_version(
        &remote_address.state,
        &mut protocol_store.store.session_store,
        None,
    ))?)
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(message_encrypt))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt_prekey))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt_signal))?;
    module.add_wrapped(wrap_pyfunction!(remote_registration_id))?;
    module.add_wrapped(wrap_pyfunction!(session_version))?;
    Ok(())
}
