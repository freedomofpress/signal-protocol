use crate::address::ProtocolAddress;
use crate::curve::{PrivateKey, PublicKey};
use crate::error::{Result,SignalProtocolError};
use crate::storage::InMemSignalProtocolStore;

use futures::executor::block_on;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

#[pyclass]
#[derive(Debug, Clone)]
pub struct ServerCertificate {
    pub data: libsignal_protocol_rust::ServerCertificate,
}

#[pymethods]
impl ServerCertificate {
    #[staticmethod]
    fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(ServerCertificate {
            data: libsignal_protocol_rust::ServerCertificate::deserialize(data)?,
        })
    }

    #[new]
    fn new(key_id: u32, key: PublicKey, trust_root: &PrivateKey) -> PyResult<Self> {
        let mut csprng = OsRng;
        match libsignal_protocol_rust::ServerCertificate::new(
            key_id,
            key.key,
            &trust_root.key,
            &mut csprng,
        ) {
            Ok(data) => Ok(Self { data }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn validate(&self, trust_root: &PublicKey) -> Result<bool> {
        Ok(self.data.validate(&trust_root.key)?)
    }

    fn key_id(&self) -> Result<u32> {
        Ok(self.data.key_id()?)
    }

    fn public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey::new(self.data.public_key()?))
    }

    fn certificate(&self, py: Python) -> Result<PyObject> {
        let result = self.data.certificate()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn signature(&self, py: Python) -> Result<PyObject> {
        let result = self.data.signature()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn serialized(&self, py: Python) -> Result<PyObject> {
        let result = self.data.serialized()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct SenderCertificate {
    pub data: libsignal_protocol_rust::SenderCertificate,
}

#[pymethods]
impl SenderCertificate {
    #[staticmethod]
    fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(SenderCertificate {
            data: libsignal_protocol_rust::SenderCertificate::deserialize(data)?,
        })
    }

    #[new]
    fn new(
        sender_uuid: Option<String>,
        sender_e164: Option<String>,
        key: PublicKey,
        sender_device_id: u32,
        expiration: u64,
        signer: ServerCertificate,
        signer_key: &PrivateKey,
    ) -> PyResult<Self> {
        let mut csprng = OsRng;
        match libsignal_protocol_rust::SenderCertificate::new(
            sender_uuid,
            sender_e164,
            key.key,
            sender_device_id,
            expiration,
            signer.data,
            &signer_key.key,
            &mut csprng,
        ) {
            Ok(data) => Ok(Self { data }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn validate(
        &self,
        trust_root: &PublicKey,
        validation_time: u64,
    ) -> Result<bool> {
        Ok(self.data.validate(&trust_root.key, validation_time)?)
    }

    fn signer(&self) -> Result<ServerCertificate> {
        Ok(ServerCertificate {
            data: (self.data.signer()?).clone(),
        })
    }

    fn key(&self) -> Result<PublicKey> {
        Ok(PublicKey::new(self.data.key()?))
    }

    fn sender_device_id(&self) -> Result<u32> {
        Ok(self.data.sender_device_id()?)
    }

    fn sender_uuid(&self) -> Result<Option<&str>> {
        Ok(self.data.sender_uuid()?)
    }

    fn sender_e164(&self) -> Result<Option<&str>> {
        Ok(self.data.sender_e164()?)
    }

    fn expiration(&self) -> Result<u64> {
        Ok(self.data.expiration()?)
    }

    fn certificate(&self, py: Python) -> Result<PyObject> {
        let result = self.data.certificate()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn signature(&self, py: Python) -> Result<PyObject> {
        let result = self.data.signature()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn serialized(&self, py: Python) -> Result<PyObject> {
        let result = self.data.serialized()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn preferred_address(
        &self,
        store: &InMemSignalProtocolStore,
    ) -> Result<ProtocolAddress> {
        Ok(ProtocolAddress {
            state: block_on(
                self.data
                    .preferred_address(&store.store.session_store, None),
            )?,
        })
    }
}

#[pyclass]
pub struct UnidentifiedSenderMessageContent {
    pub data: libsignal_protocol_rust::UnidentifiedSenderMessageContent,
}

#[pymethods]
impl UnidentifiedSenderMessageContent {
    #[staticmethod]
    fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(UnidentifiedSenderMessageContent {
            data: libsignal_protocol_rust::UnidentifiedSenderMessageContent::deserialize(data)?,
        })
    }

    #[new]
    fn new(msg_type_value: u8, sender: SenderCertificate, contents: Vec<u8>) -> PyResult<Self> {
        let msg_enum = match msg_type_value {
            2 => libsignal_protocol_rust::CiphertextMessageType::Whisper,
            3 => libsignal_protocol_rust::CiphertextMessageType::PreKey,
            4 => libsignal_protocol_rust::CiphertextMessageType::SenderKey,
            5 => libsignal_protocol_rust::CiphertextMessageType::SenderKeyDistribution,
            _ => {
                return Err(SignalProtocolError::err_from_str(format!(
                    "unknown message type: {}",
                    msg_type_value
                )))
            }
        };
        match libsignal_protocol_rust::UnidentifiedSenderMessageContent::new(
            msg_enum,
            sender.data,
            contents,
        ) {
            Ok(data) => Ok(Self { data }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn msg_type(&self) -> Result<u8> {
        Ok(self.data.msg_type()? as u8)
    }

    fn sender(&self) -> Result<SenderCertificate> {
        Ok(SenderCertificate {
            data: (self.data.sender()?).clone(),
        })
    }

    fn contents(&self, py: Python) -> Result<PyObject> {
        let result = self.data.contents()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn serialized(&self, py: Python) -> Result<PyObject> {
        let result = self.data.serialized()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

#[pyclass]
pub struct UnidentifiedSenderMessage {
    pub data: libsignal_protocol_rust::UnidentifiedSenderMessage,
}

#[pymethods]
impl UnidentifiedSenderMessage {
    #[staticmethod]
    fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(UnidentifiedSenderMessage {
            data: libsignal_protocol_rust::UnidentifiedSenderMessage::deserialize(data)?,
        })
    }

    #[new]
    fn new(
        ephemeral_public: PublicKey,
        encrypted_static: Vec<u8>,
        encrypted_message: Vec<u8>,
    ) -> PyResult<Self> {
        match libsignal_protocol_rust::UnidentifiedSenderMessage::new(
            ephemeral_public.key,
            encrypted_static,
            encrypted_message,
        ) {
            Ok(data) => Ok(Self { data }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn version(&self) -> Result<u8> {
        Ok(self.data.version()?)
    }

    fn ephemeral_public(&self) -> Result<PublicKey> {
        Ok(PublicKey::new(self.data.ephemeral_public()?))
    }

    fn encrypted_static(&self, py: Python) -> Result<PyObject> {
        let result = self.data.encrypted_static()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn encrypted_message(&self, py: Python) -> Result<PyObject> {
        let result = self.data.encrypted_message()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn serialized(&self, py: Python) -> Result<PyObject> {
        let result = self.data.serialized()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

#[pyclass]
pub struct SealedSenderDecryptionResult {
    pub data: libsignal_protocol_rust::SealedSenderDecryptionResult,
}

#[pymethods]
impl SealedSenderDecryptionResult {
    pub fn sender_uuid(&self) -> Option<String> {
        self.data.sender_uuid.clone()
    }

    pub fn sender_e164(&self) -> Option<String> {
        self.data.sender_e164.clone()
    }

    pub fn device_id(&self) -> u32 {
        self.data.device_id
    }

    fn message(&self, py: Python) -> Result<PyObject> {
        Ok(PyBytes::new(py, &self.data.message).into())
    }
}

#[pyfunction]
pub fn sealed_sender_decrypt(
    ciphertext: &[u8],
    trust_root: &PublicKey,
    timestamp: u64,
    local_e164: Option<String>,
    local_uuid: Option<String>,
    local_device_id: u32,
    protocol_store: &mut InMemSignalProtocolStore,
) -> PyResult<SealedSenderDecryptionResult> {
    match block_on(libsignal_protocol_rust::sealed_sender_decrypt(
        ciphertext,
        &trust_root.key,
        timestamp,
        local_e164,
        local_uuid,
        local_device_id,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        None,
    )) {
        Ok(data) => Ok(SealedSenderDecryptionResult { data }),
        Err(err) => Err(SignalProtocolError::new_err(err)),
    }
}

#[pyfunction]
pub fn sealed_sender_encrypt(
    destination: &ProtocolAddress,
    sender_cert: &SenderCertificate,
    ptext: &[u8],
    protocol_store: &mut InMemSignalProtocolStore,
    py: Python,
) -> Result<PyObject> {
    let mut csprng = OsRng;
    let result = block_on(libsignal_protocol_rust::sealed_sender_encrypt(
        &destination.state,
        &sender_cert.data,
        ptext,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        None,
        &mut csprng,
    ))?;
    Ok(PyBytes::new(py, &result).into())
}

#[pyfunction]
pub fn sealed_sender_decrypt_to_usmc(
    ciphertext: &[u8],
    protocol_store: &mut InMemSignalProtocolStore,
) -> PyResult<UnidentifiedSenderMessageContent> {
    match block_on(libsignal_protocol_rust::sealed_sender_decrypt_to_usmc(
        ciphertext,
        &mut protocol_store.store.identity_store,
        None,
    )) {
        Ok(data) => Ok(UnidentifiedSenderMessageContent { data }),
        Err(err) => Err(SignalProtocolError::new_err(err)),
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<SenderCertificate>()?;
    module.add_class::<ServerCertificate>()?;
    module.add_class::<UnidentifiedSenderMessageContent>()?;
    module.add_class::<UnidentifiedSenderMessage>()?;
    module.add_class::<SealedSenderDecryptionResult>()?;
    module.add_wrapped(wrap_pyfunction!(sealed_sender_decrypt))?;
    module.add_wrapped(wrap_pyfunction!(sealed_sender_decrypt_to_usmc))?;
    module.add_wrapped(wrap_pyfunction!(sealed_sender_encrypt))?;
    Ok(())
}
