use std::convert::TryFrom;

use pyo3::prelude::*;
use pyo3::pyclass::PyClassAlloc;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use pyo3::exceptions;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

use crate::address::ProtocolAddress;
use crate::curve::PublicKey;
use crate::identity_key::IdentityKey;
use crate::state::PreKeyBundle;
use crate::storage::InMemSignalProtocolStore;

/// CiphertextMessage is a Rust enum in the upstream crate. Mapping of enums is not supported
/// in pyo3.
/// Approach: Map Rust enum and its variants to Python as a superclass and subclasses.
/// Subtype relation for Rust variant (PreKeySignalMessage) and its enum:
/// PreKeySignalMessage <: CiphertextMessage
/// In Python the subclass/superclass has the same subtype relation (subclass <: superclass).
#[pyclass]
pub struct CiphertextMessage {
    pub data: libsignal_protocol_rust::CiphertextMessage
}

impl CiphertextMessage {
    pub fn new(data: libsignal_protocol_rust::CiphertextMessage) -> Self {
        CiphertextMessage{ data }
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
#[pyclass(extends=CiphertextMessage)]
pub struct PreKeySignalMessage {
    pub data: libsignal_protocol_rust::PreKeySignalMessage
}

#[pymethods]
impl PreKeySignalMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<CiphertextMessage> {
        Ok(CiphertextMessage{ data: libsignal_protocol_rust::CiphertextMessage::PreKeySignalMessage(libsignal_protocol_rust::PreKeySignalMessage::try_from(data).unwrap()) })
    }

    pub fn serialized(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, &self.data.serialized()).into())
    }
}

/// CiphertextMessageType::Whisper
#[pyclass]
pub struct SignalMessage {
    pub data: libsignal_protocol_rust::CiphertextMessage
}

#[pymethods]
impl SignalMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<CiphertextMessage> {
        Ok(CiphertextMessage{ data: libsignal_protocol_rust::CiphertextMessage::SignalMessage(libsignal_protocol_rust::SignalMessage::try_from(data).unwrap()) })
    }

    #[new]
    pub fn new(message_version: u8,
        mac_key: &[u8],
        sender_ratchet_key: PublicKey,
        counter: u32,
        previous_counter: u32,
        ciphertext: &[u8],
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey
    ) -> (Self, CiphertextMessage) {
        let msg = libsignal_protocol_rust::CiphertextMessage::SignalMessage(libsignal_protocol_rust::SignalMessage::new(
            message_version,
            mac_key,
            sender_ratchet_key.key,
            counter,
            previous_counter,
            &ciphertext,
            &sender_identity_key.key,
            &receiver_identity_key.key
        ).unwrap());
        (
            SignalMessage{ data: msg },
            CiphertextMessage::new(msg)
        )
    }
}

/// CiphertextMessageType::SenderKey => 4
#[pyclass]
pub struct SenderKeyMessage {
    pub data: libsignal_protocol_rust::SenderKeyMessage
}

#[pymethods]
impl SenderKeyMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<CiphertextMessage> {
        Ok(CiphertextMessage{ data: libsignal_protocol_rust::CiphertextMessage::SenderKeyMessage(libsignal_protocol_rust::SenderKeyMessage::try_from(data).unwrap()) })
    }
}

/// CiphertextMessageType::SenderKeyDistribution => 5
#[pyclass]
pub struct SenderKeyDistributionMessage {
    pub data: libsignal_protocol_rust::SenderKeyDistributionMessage
}

#[pymethods]
impl SenderKeyDistributionMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<CiphertextMessage> {
        Ok(CiphertextMessage{ data: libsignal_protocol_rust::CiphertextMessage::SenderKeyDistributionMessage(libsignal_protocol_rust::SenderKeyDistributionMessage::try_from(data).unwrap()) })
    }
}

/// CiphertextMessageType is an Enum that is not exposed as part
/// of the Python API.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<CiphertextMessage>()?;
    module.add_class::<PreKeySignalMessage>()?;
    module.add_class::<SignalMessage>()?;
    module.add_class::<SenderKeyMessage>()?;
    module.add_class::<SenderKeyDistributionMessage>()?;
    Ok(())
}
