use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use crate::identity_key::{IdentityKey, IdentityKeyPair};
use libsignal_protocol_rust;
use libsignal_protocol_rust::IdentityKeyStore;


#[pyclass]
pub struct InMemSignalProtocolStore {
    pub store: libsignal_protocol_rust::InMemSignalProtocolStore
}

#[pymethods]
impl InMemSignalProtocolStore {
    #[new]
    fn new(key_pair: &IdentityKeyPair, registration_id: u32) -> PyResult<InMemSignalProtocolStore> {
        Ok(Self{
            store: libsignal_protocol_rust::InMemSignalProtocolStore::new(key_pair.key, registration_id).unwrap(),
        })
    }
}

/// libsignal_protocol_rust::IdentityKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_identity_key_pair(&self) -> PyResult<IdentityKeyPair> {
        let result = self.store.identity_store.get_identity_key_pair(None).unwrap();
        Ok(IdentityKeyPair{ key: result })
    }

    // TO FIGURE OUT: Exceptions
    // fn get_local_registration_id(&self) -> PyResult<u32> {
    //     Ok(self.store.identity_store.get_local_registration_id(None)?)
    // }

    // fn save_identity(
    //     &mut self,
    //     address: &ProtocolAddress,
    //     identity: &IdentityKey,
    //     ctx: Context,
    // ) -> Result<bool> {
    //     self.identity_store.save_identity(address, identity, ctx)
    // }

    // fn is_trusted_identity(
    //     &self,
    //     address: &ProtocolAddress,
    //     identity: &IdentityKey,
    //     direction: traits::Direction,
    //     ctx: Context,
    // ) -> Result<bool> {
    //     self.identity_store
    //         .is_trusted_identity(address, identity, direction, ctx)
    // }

    // fn get_identity(&self, address: &ProtocolAddress, ctx: Context) -> Result<Option<IdentityKey>> {
    //     self.identity_store.get_identity(address, ctx)
    // }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<InMemSignalProtocolStore>()?;
    Ok(())
}
