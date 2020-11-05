use pyo3::prelude::*;
use pyo3::pyclass::PyClassAlloc;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use pyo3::exceptions;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

use crate::address::ProtocolAddress;
use crate::error::SignalProtocolError;
use crate::protocol::{PreKeySignalMessage,CiphertextMessage};
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

    Ok(CiphertextMessage::new(ciphertext.unwrap()))
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
        Ok(result)  => Ok(PyBytes::new(py, &result).into()),
        Err(_e) => Err(SignalProtocolError::new_err("unknown decryption error"))
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(message_encrypt))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt))?;
    Ok(())
}
