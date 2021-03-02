use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::address::ProtocolAddress;
use crate::curve::{PrivateKey, PublicKey};
use crate::error::{Result, SignalProtocolError};

#[pyclass]
#[derive(Clone, Debug)]
pub struct SenderKeyName {
    pub state: libsignal_protocol_rust::SenderKeyName,
}

#[pymethods]
impl SenderKeyName {
    #[new]
    fn new(group_id: String, sender: ProtocolAddress) -> PyResult<SenderKeyName> {
        match libsignal_protocol_rust::SenderKeyName::new(group_id, sender.state) {
            Ok(state) => Ok(Self { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn group_id(&self) -> Result<String> {
        Ok(self.state.group_id()?)
    }

    pub fn sender_name(&self) -> Result<String> {
        Ok(self.state.sender_name()?)
    }

    pub fn sender_device_id(&self) -> Result<u32> {
        Ok(self.state.sender_device_id()?)
    }

    pub fn sender(&self) -> Result<ProtocolAddress> {
        Ok(ProtocolAddress {
            state: self.state.sender()?,
        })
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct SenderKeyRecord {
    pub state: libsignal_protocol_rust::SenderKeyRecord,
}

/// as_protobuf are not implemented on the Python API.
#[pymethods]
impl SenderKeyRecord {
    #[staticmethod]
    pub fn new_empty() -> Self {
        Self {
            state: libsignal_protocol_rust::SenderKeyRecord::new_empty(),
        }
    }

    #[staticmethod]
    pub fn deserialize(buf: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::SenderKeyRecord::deserialize(buf) {
            Ok(state) => Ok(Self { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.state.is_empty()?)
    }

    pub fn add_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<()> {
        let sig_private_key = match signature_private_key {
            Some(key) => Some(key.key),
            None => None,
        };
        Ok(self.state.add_sender_key_state(
            id,
            iteration,
            chain_key,
            signature_key.key,
            sig_private_key,
        )?)
    }

    pub fn set_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<()> {
        let sig_private_key = match signature_private_key {
            Some(key) => Some(key.key),
            None => None,
        };
        Ok(self.state.set_sender_key_state(
            id,
            iteration,
            chain_key,
            signature_key.key,
            sig_private_key,
        )?)
    }

    pub fn serialize(&self, py: Python) -> Result<PyObject> {
        let bytes = self.state.serialize()?;
        Ok(PyBytes::new(py, &bytes).into())
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<SenderKeyName>()?;
    module.add_class::<SenderKeyRecord>()?;
    Ok(())
}
