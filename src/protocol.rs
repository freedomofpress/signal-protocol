use pyo3::prelude::*;
use pyo3::pyclass::PyClassAlloc;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use pyo3::exceptions;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

use crate::address::ProtocolAddress;
use crate::state::PreKeyBundle;
use crate::storage::InMemSignalProtocolStore;

#[pyclass]
pub struct CiphertextMessage {
    pub data: libsignal_protocol_rust::CiphertextMessage
}

impl CiphertextMessage {
    pub fn new(data: libsignal_protocol_rust::CiphertextMessage) -> Self {
        CiphertextMessage{ data }
    }
}

/// AFAIK there isn't a way to translate Enums from Rust to Python using PyO3, so
/// we're using the following mapping of libsignal_protocol_rust::CiphertextMessageType to u8:
/// CiphertextMessageType::Whisper => 2
/// CiphertextMessageType::PreKey => 3
/// CiphertextMessageType::SenderKey => 4
/// CiphertextMessageType::SenderKeyDistribution => 5
#[pymethods]
impl CiphertextMessage {
    pub fn serialize(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, self.data.serialize()).into())
    }

    pub fn message_type(&self) -> u8 {
        self.data.message_type().encoding()
    }
}


pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<CiphertextMessage>()?;
    Ok(())
}
