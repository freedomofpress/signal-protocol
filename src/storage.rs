use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use crate::identity_key::{IdentityKey, IdentityKeyPair};
use libsignal_protocol_rust;


#[pyclass]
pub struct InMemSignalProtocolStoreWrapper {
    pub store: libsignal_protocol_rust::InMemSignalProtocolStore
}

#[pymethods]
impl InMemSignalProtocolStoreWrapper {
    #[new]
    fn new(key_pair: &IdentityKeyPair, registration_id: u32) -> InMemSignalProtocolStoreWrapper {
        Self{
            store: libsignal_protocol_rust::InMemSignalProtocolStore::new(key_pair.key, registration_id).unwrap(),
        }
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<InMemSignalProtocolStoreWrapper>()?;
    Ok(())
}
