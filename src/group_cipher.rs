use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use futures::executor::block_on;
use rand::rngs::OsRng;

use crate::error::SignalProtocolError;
use crate::protocol::{CiphertextMessage, SenderKeyDistributionMessage};
use crate::sender_keys::SenderKeyName;
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn group_encrypt(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    sender_key_id: &SenderKeyName,
    plaintext: &[u8],
) -> Result<PyObject, SignalProtocolError> {
    let mut csprng = OsRng;
    let ciphertext = block_on(libsignal_protocol_rust::group_encrypt(
        &mut protocol_store.store.sender_key_store,
        &sender_key_id.state,
        plaintext,
        &mut csprng,
        None,
    ))?;
    Ok(PyBytes::new(py, &ciphertext).into())
}

#[pyfunction]
pub fn group_decrypt(
    py: Python,
    skm_bytes: &[u8],
    protocol_store: &mut InMemSignalProtocolStore,
    sender_key_id: &SenderKeyName,
) -> Result<PyObject, SignalProtocolError> {
    let plaintext = block_on(libsignal_protocol_rust::group_decrypt(
        skm_bytes,
        &mut protocol_store.store.sender_key_store,
        &sender_key_id.state,
        None,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn process_sender_key_distribution_message(
    sender_key_name: &SenderKeyName,
    skdm: &SenderKeyDistributionMessage,
    protocol_store: &mut InMemSignalProtocolStore,
) -> Result<(), SignalProtocolError> {
    Ok(block_on(
        libsignal_protocol_rust::process_sender_key_distribution_message(
            &sender_key_name.state,
            &skdm.data,
            &mut protocol_store.store.sender_key_store,
            None,
        ),
    )?)
}

#[pyfunction]
pub fn create_sender_key_distribution_message(
    sender_key_name: &SenderKeyName,
    protocol_store: &mut InMemSignalProtocolStore,
) -> PyResult<Py<SenderKeyDistributionMessage>> {
    let mut csprng = OsRng;
    let upstream_data = match block_on(
        libsignal_protocol_rust::create_sender_key_distribution_message(
            &sender_key_name.state,
            &mut protocol_store.store.sender_key_store,
            &mut csprng,
            None,
        ),
    ) {
        Ok(data) => data,
        Err(err) => return Err(SignalProtocolError::new_err(err)),
    };
    let ciphertext = libsignal_protocol_rust::CiphertextMessage::SenderKeyDistributionMessage(
        upstream_data.clone(),
    );

    // The CiphertextMessage is required as it is the base class for SenderKeyDistributionMessage
    // on the Python side, so we must create _both_ a CiphertextMessage and a SenderKeyDistributionMessage
    // on the Rust side for inheritance to work.
    let gil = Python::acquire_gil();
    let py = gil.python();
    Py::new(
        py,
        (
            SenderKeyDistributionMessage {
                data: upstream_data,
            },
            CiphertextMessage { data: ciphertext },
        ),
    )
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(group_encrypt))?;
    module.add_wrapped(wrap_pyfunction!(group_decrypt))?;
    module.add_wrapped(wrap_pyfunction!(process_sender_key_distribution_message))?;
    module.add_wrapped(wrap_pyfunction!(create_sender_key_distribution_message))?;
    Ok(())
}
