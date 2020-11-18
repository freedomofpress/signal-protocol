use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::pyclass::PyClassAlloc;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

use crate::address::ProtocolAddress;
use crate::error::SignalProtocolError;
use crate::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use crate::state::PreKeyBundle;
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn message_encrypt(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &str,
) -> PyResult<CiphertextMessage> {
    let ciphertext = libsignal_protocol_rust::message_encrypt(
        msg.as_bytes(),
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        None,
    );

    match ciphertext {
        Ok(result) => Ok(CiphertextMessage::new(result)),
        Err(_e) => Err(SignalProtocolError::new_err("unknown encryption error")),
    }
}

#[pyfunction]
pub fn message_decrypt(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &CiphertextMessage,
) -> PyResult<PyObject> {
    let mut csprng = OsRng;
    let plaintext = libsignal_protocol_rust::message_decrypt(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        &mut csprng,
        None,
    );
    match plaintext {
        Ok(result) => Ok(PyBytes::new(py, &result).into()),
        Err(_e) => Err(SignalProtocolError::new_err("unknown decryption error")),
    }
}

#[pyfunction]
pub fn message_decrypt_prekey(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &PreKeySignalMessage,
) -> PyResult<PyObject> {
    let mut csprng = OsRng;
    let plaintext = libsignal_protocol_rust::message_decrypt_prekey(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        &mut csprng,
        None,
    );
    match plaintext {
        Ok(result) => Ok(PyBytes::new(py, &result).into()),
        Err(_e) => Err(SignalProtocolError::new_err("unknown decryption error")),
    }
}

#[pyfunction]
pub fn message_decrypt_signal(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &SignalMessage,
) -> PyResult<PyObject> {
    let mut csprng = OsRng;
    let plaintext = libsignal_protocol_rust::message_decrypt_signal(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut csprng,
        None,
    );
    match plaintext {
        Ok(result) => Ok(PyBytes::new(py, &result).into()),
        Err(_e) => Err(SignalProtocolError::new_err("unknown decryption error")),
    }
}

#[pyfunction]
pub fn remote_registration_id(
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
) -> PyResult<u32> {
    match libsignal_protocol_rust::remote_registration_id(
        &remote_address.state,
        &mut protocol_store.store.session_store,
        None,
    ) {
        Ok(result) => Ok(result),
        Err(_e) => Err(SignalProtocolError::new_err(
            "could not get remote registration id",
        )),
    }
}

#[pyfunction]
pub fn session_version(
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
) -> PyResult<u32> {
    match libsignal_protocol_rust::session_version(
        &remote_address.state,
        &mut protocol_store.store.session_store,
        None,
    ) {
        Ok(result) => Ok(result),
        Err(_e) => Err(SignalProtocolError::new_err(
            "could not get remote registration id",
        )),
    }
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
