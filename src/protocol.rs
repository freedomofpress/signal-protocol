use std::convert::TryFrom;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass]
pub struct CiphertextMessage {
    pub data: libsignal_protocol_rust::CiphertextMessage,
}

impl CiphertextMessage {
    pub fn new(data: libsignal_protocol_rust::CiphertextMessage) -> Self {
        CiphertextMessage { data }
    }
}

/// We're using the following mapping of libsignal_protocol_rust::CiphertextMessageType to u8:
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

/// CiphertextMessageType::PreKey => 3
#[pyclass]
pub struct PreKeySignalMessage {
    pub data: libsignal_protocol_rust::PreKeySignalMessage,
}

/// Rust enums cannot be mapped to Python enums in PyO3. This means
/// that here PreKeySignalMessage is not a subtype of CiphertextMessage.
/// This means if we try to use PreKeySignalMessage in e.g.
/// session_cipher::message_decrypt, we'll get a type error as those methods
/// require CiphertextMessage.
///
/// We handle this by having the try_from constructor on PreKeySignalMessage
/// actually create a CiphertextMessage under the hood. (TODO: better solution here?)
#[pymethods]
impl PreKeySignalMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<CiphertextMessage> {
        Ok(CiphertextMessage {
            data: libsignal_protocol_rust::CiphertextMessage::PreKeySignalMessage(
                libsignal_protocol_rust::PreKeySignalMessage::try_from(data).unwrap(),
            ),
        })
    }

    pub fn serialized(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.data.serialized()).into())
    }
}

/// CiphertextMessageType::Whisper
#[pyclass]
pub struct SignalMessage {
    pub data: libsignal_protocol_rust::SignalMessage,
}

#[pymethods]
impl SignalMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<CiphertextMessage> {
        Ok(CiphertextMessage {
            data: libsignal_protocol_rust::CiphertextMessage::SignalMessage(
                libsignal_protocol_rust::SignalMessage::try_from(data).unwrap(),
            ),
        })
    }
}

/// CiphertextMessageType::SenderKey => 4
#[pyclass]
pub struct SenderKeyMessage {
    pub data: libsignal_protocol_rust::SenderKeyMessage,
}

#[pymethods]
impl SenderKeyMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<CiphertextMessage> {
        Ok(CiphertextMessage {
            data: libsignal_protocol_rust::CiphertextMessage::SenderKeyMessage(
                libsignal_protocol_rust::SenderKeyMessage::try_from(data).unwrap(),
            ),
        })
    }
}

/// CiphertextMessageType::SenderKeyDistribution => 5
#[pyclass]
pub struct SenderKeyDistributionMessage {
    pub data: libsignal_protocol_rust::SenderKeyDistributionMessage,
}

#[pymethods]
impl SenderKeyDistributionMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<CiphertextMessage> {
        Ok(CiphertextMessage {
            data: libsignal_protocol_rust::CiphertextMessage::SenderKeyDistributionMessage(
                libsignal_protocol_rust::SenderKeyDistributionMessage::try_from(data).unwrap(),
            ),
        })
    }
}

/// CiphertextMessageType is an Enum that cannot yet be exposed as part
/// of the Python API.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<CiphertextMessage>()?;
    module.add_class::<PreKeySignalMessage>()?;
    module.add_class::<SignalMessage>()?;
    module.add_class::<SenderKeyMessage>()?;
    module.add_class::<SenderKeyDistributionMessage>()?;
    Ok(())
}
