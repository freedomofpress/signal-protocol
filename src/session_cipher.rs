use pyo3::prelude::*;
use pyo3::pyclass::PyClassAlloc;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use pyo3::exceptions;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

use crate::address::ProtocolAddress;
use crate::protocol::CiphertextMessage;
use crate::state::PreKeyBundle;
use crate::storage::InMemSignalProtocolStore;


/// Eventually return PyResult<CiphertextMessage>
#[pyfunction]
pub fn encrypt(
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

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(encrypt))?;
    Ok(())
}
