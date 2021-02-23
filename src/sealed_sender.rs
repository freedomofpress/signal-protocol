use crate::address::ProtocolAddress;
use crate::curve::{PrivateKey, PublicKey};
use crate::error::SignalProtocolError;
use crate::storage::InMemSignalProtocolStore;

use futures::executor::block_on;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::rngs::OsRng;

#[pyclass]
#[derive(Debug, Clone)]
pub struct ServerCertificate {
    pub data: libsignal_protocol_rust::ServerCertificate,
}

#[pymethods]
impl ServerCertificate {
    #[staticmethod]
    fn deserialize(data: &[u8]) -> Result<Self, SignalProtocolError> {
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

    fn validate(&self, trust_root: &PublicKey) -> Result<bool, SignalProtocolError> {
        Ok(self.data.validate(&trust_root.key)?)
    }

    fn key_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.data.key_id()?)
    }

    fn public_key(&self) -> Result<PublicKey, SignalProtocolError> {
        Ok(PublicKey::new(self.data.public_key()?))
    }

    fn certificate(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.data.certificate()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn signature(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.data.signature()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn serialized(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
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
    fn deserialize(data: &[u8]) -> Result<Self, SignalProtocolError> {
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
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.data.validate(&trust_root.key, validation_time)?)
    }

    fn signer(&self) -> Result<ServerCertificate, SignalProtocolError> {
        Ok(ServerCertificate {
            data: (self.data.signer()?).clone(),
        })
    }

    fn key(&self) -> Result<PublicKey, SignalProtocolError> {
        Ok(PublicKey::new(self.data.key()?))
    }

    fn sender_device_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.data.sender_device_id()?)
    }

    fn sender_uuid(&self) -> Result<Option<&str>, SignalProtocolError> {
        Ok(self.data.sender_uuid()?)
    }

    fn sender_e164(&self) -> Result<Option<&str>, SignalProtocolError> {
        Ok(self.data.sender_e164()?)
    }

    fn expiration(&self) -> Result<u64, SignalProtocolError> {
        Ok(self.data.expiration()?)
    }

    fn certificate(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.data.certificate()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn signature(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.data.signature()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn serialized(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.data.serialized()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn preferred_address(
        &self,
        store: &InMemSignalProtocolStore,
    ) -> Result<ProtocolAddress, SignalProtocolError> {
        Ok(ProtocolAddress {
            state: block_on(
                self.data
                    .preferred_address(&store.store.session_store, None),
            )?,
        })
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<SenderCertificate>()?;
    module.add_class::<ServerCertificate>()?;
    Ok(())
}
