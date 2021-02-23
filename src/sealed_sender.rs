use crate::curve::{PrivateKey, PublicKey};
use crate::error::SignalProtocolError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::rngs::OsRng;

#[pyclass]
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

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    //module.add_class::<SenderCertificate>()?;
    module.add_class::<ServerCertificate>()?;
    Ok(())
}
