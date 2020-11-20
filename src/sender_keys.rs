use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::address::ProtocolAddress;
use crate::curve::{PrivateKey, PublicKey};
use crate::error::SignalProtocolError;

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

    pub fn group_id(&self) -> Result<String, SignalProtocolError> {
        Ok(self.state.group_id()?)
    }

    pub fn sender_name(&self) -> Result<String, SignalProtocolError> {
        Ok(self.state.sender_name()?)
    }

    pub fn sender_device_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.sender_device_id()?)
    }

    pub fn sender(&self) -> Result<ProtocolAddress, SignalProtocolError> {
        Ok(ProtocolAddress {
            state: self.state.sender()?,
        })
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct SenderMessageKey {
    pub state: libsignal_protocol_rust::SenderMessageKey,
}

/// from_protobuf and as_protobuf are not exposed as part of the Python API.
#[pymethods]
impl SenderMessageKey {
    #[new]
    fn new(iteration: u32, seed: Vec<u8>) -> PyResult<Self> {
        match libsignal_protocol_rust::SenderMessageKey::new(iteration, seed) {
            Ok(state) => Ok(Self { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn iteration(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.iteration()?)
    }

    pub fn iv(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let iv = self.state.iv()?;
        Ok(PyBytes::new(py, &iv).into())
    }

    pub fn cipher_key(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let key = self.state.cipher_key()?;
        Ok(PyBytes::new(py, &key).into())
    }

    pub fn seed(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let seed = self.state.seed()?;
        Ok(PyBytes::new(py, &seed).into())
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct SenderChainKey {
    pub state: libsignal_protocol_rust::SenderChainKey,
}

/// as_protobuf is not exposed as part of the Python API.
#[pymethods]
impl SenderChainKey {
    #[new]
    pub fn new(iteration: u32, chain_key: Vec<u8>) -> PyResult<Self> {
        match libsignal_protocol_rust::SenderChainKey::new(iteration, chain_key) {
            Ok(state) => Ok(Self { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn iteration(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.iteration()?)
    }

    pub fn seed(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let seed = self.state.seed()?;
        Ok(PyBytes::new(py, &seed).into())
    }

    pub fn next(&self) -> Result<SenderChainKey, SignalProtocolError> {
        Ok(SenderChainKey {
            state: self.state.next()?,
        })
    }

    pub fn sender_message_key(&self) -> Result<SenderMessageKey, SignalProtocolError> {
        Ok(SenderMessageKey {
            state: self.state.sender_message_key()?,
        })
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct SenderKeyState {
    pub state: libsignal_protocol_rust::SenderKeyState,
}

/// from_protobuf and as_protobuf are not implemented on the Python API.
#[pymethods]
impl SenderKeyState {
    #[new]
    pub fn new(
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> PyResult<Self> {
        let sig_private_key = match signature_private_key {
            Some(key) => Some(key.key),
            None => None,
        };

        match libsignal_protocol_rust::SenderKeyState::new(
            id,
            iteration,
            chain_key,
            signature_key.key,
            sig_private_key,
        ) {
            Ok(state) => Ok(Self { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    #[staticmethod]
    pub fn deserialize(buf: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::SenderKeyState::deserialize(buf) {
            Ok(state) => Ok(SenderKeyState { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn serialize(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let bytes = self.state.serialize()?;
        Ok(PyBytes::new(py, &bytes).into())
    }

    pub fn sender_key_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.sender_key_id()?)
    }

    pub fn sender_chain_key(&self) -> Result<SenderChainKey, SignalProtocolError> {
        Ok(SenderChainKey {
            state: self.state.sender_chain_key()?,
        })
    }

    pub fn set_sender_chain_key(
        &mut self,
        chain_key: SenderChainKey,
    ) -> Result<(), SignalProtocolError> {
        Ok(self.state.set_sender_chain_key(chain_key.state)?)
    }

    pub fn signing_key_public(&self) -> Result<PublicKey, SignalProtocolError> {
        Ok(PublicKey {
            key: self.state.signing_key_public()?,
        })
    }

    pub fn signing_key_private(&self) -> Result<Option<PrivateKey>, SignalProtocolError> {
        match self.state.signing_key_private()? {
            Some(key) => Ok(Some(PrivateKey { key })),
            None => Ok(None),
        }
    }

    pub fn has_sender_message_key(&self, iteration: u32) -> Result<bool, SignalProtocolError> {
        Ok(self.state.has_sender_message_key(iteration)?)
    }

    pub fn add_sender_message_key(
        &mut self,
        sender_message_key: &SenderMessageKey,
    ) -> Result<(), SignalProtocolError> {
        Ok(self
            .state
            .add_sender_message_key(&sender_message_key.state)?)
    }

    pub fn remove_sender_message_key(
        &mut self,
        iteration: u32,
    ) -> Result<Option<SenderMessageKey>, SignalProtocolError> {
        match self.state.remove_sender_message_key(iteration)? {
            Some(state) => Ok(Some(SenderMessageKey { state })),
            None => Ok(None),
        }
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

    pub fn is_empty(&self) -> Result<bool, SignalProtocolError> {
        Ok(self.state.is_empty()?)
    }

    pub fn sender_key_state(&mut self) -> Result<SenderKeyState, SignalProtocolError> {
        Ok(SenderKeyState {
            state: self.state.sender_key_state()?.clone(),
        })
    }

    pub fn sender_key_state_for_keyid(
        &mut self,
        key_id: u32,
    ) -> Result<SenderKeyState, SignalProtocolError> {
        Ok(SenderKeyState {
            state: self.state.sender_key_state_for_keyid(key_id)?.clone(),
        })
    }

    pub fn add_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<(), SignalProtocolError> {
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
    ) -> Result<(), SignalProtocolError> {
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

    pub fn serialize(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let bytes = self.state.serialize()?;
        Ok(PyBytes::new(py, &bytes).into())
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<SenderKeyName>()?;
    module.add_class::<SenderMessageKey>()?;
    module.add_class::<SenderChainKey>()?;
    module.add_class::<SenderKeyState>()?;
    module.add_class::<SenderKeyRecord>()?;
    Ok(())
}
