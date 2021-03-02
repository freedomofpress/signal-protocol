use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use futures::executor::block_on;
use rand::rngs::OsRng;

use crate::address::ProtocolAddress;
use crate::error::Result;
use crate::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn message_encrypt(
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &[u8],
) -> Result<CiphertextMessage> {
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
) -> Result<PyObject> {
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
) -> Result<PyObject> {
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
) -> Result<PyObject> {
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

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(message_encrypt))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt_prekey))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt_signal))?;
    Ok(())
}
