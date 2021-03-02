use pyo3::class::basic::PyObjectProtocol;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::{Result, SignalProtocolError};
use crate::identity_key::IdentityKey;

#[pyclass]
#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub state: libsignal_protocol_rust::Fingerprint,
}

#[pymethods]
impl Fingerprint {
    #[new]
    pub fn new(
        version: u32,
        iterations: u32,
        local_id: &[u8],
        local_key: &IdentityKey,
        remote_id: &[u8],
        remote_key: &IdentityKey,
    ) -> PyResult<Self> {
        match libsignal_protocol_rust::Fingerprint::new(
            version,
            iterations,
            local_id,
            &local_key.key,
            remote_id,
            &remote_key.key,
        ) {
            Ok(state) => Ok(Self { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn display_string(&self) -> Result<String> {
        Ok(self.state.display_string()?)
    }

    pub fn compare(&self, combined: &[u8]) -> Result<bool> {
        Ok(self.state.scannable.compare(combined)?)
    }

    pub fn serialize(&self, py: Python) -> Result<PyObject> {
        let fingerprint = self.state.scannable.serialize()?;
        Ok(PyBytes::new(py, &fingerprint).into())
    }
}

#[pyproto]
impl PyObjectProtocol for Fingerprint {
    fn __str__(&self) -> Result<String> {
        self.display_string()
    }

    fn __repr__(&self) -> Result<String> {
        self.display_string()
    }
}

/// Instead of DisplayableFingerprint, ScannableFingerprint, and Fingerprint, we
/// just expose Fingerprint, with the relevant methods on the DisplayableFingerprint
/// and ScannableFingerprint implemented on the Fingerprint directly.
///
/// ScannableFingerprint::deserialize() is not implemented.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<Fingerprint>()?;
    Ok(())
}
