use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use crate::address::ProtocolAddress;
use crate::error::SignalProtocolError;
use crate::identity_key::{IdentityKey, IdentityKeyPair};
use crate::session::SessionRecord;
use crate::state::{PreKeyId,PreKeyRecord,SignedPreKeyRecord,SignedPreKeyId};

use libsignal_protocol_rust;
// traits
use libsignal_protocol_rust::{SessionStore, IdentityKeyStore, PreKeyStore, SignedPreKeyStore};

#[pyclass]
pub struct InMemSignalProtocolStore {
    pub store: libsignal_protocol_rust::InMemSignalProtocolStore,
}

#[pymethods]
impl InMemSignalProtocolStore {
    #[new]
    fn new(key_pair: &IdentityKeyPair, registration_id: u32) -> PyResult<InMemSignalProtocolStore> {
        Ok(Self {
            store: libsignal_protocol_rust::InMemSignalProtocolStore::new(
                key_pair.key,
                registration_id,
            )
            .unwrap(),
        })
    }
}

/// libsignal_protocol_rust::IdentityKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_identity_key_pair(&self) -> PyResult<IdentityKeyPair> {
        let result = self
            .store
            .identity_store
            .get_identity_key_pair(None)
            .unwrap();
        Ok(IdentityKeyPair { key: result })
    }

    fn get_local_registration_id(&self) -> PyResult<u32> {
        Ok(self
            .store
            .identity_store
            .get_local_registration_id(None)
            .unwrap())
    }

    fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> PyResult<bool> {

        Ok(self.store.identity_store.save_identity(&address.state, &identity.key, None).unwrap())
    }

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

/// libsignal_protocol_rust::SessionStore
#[pymethods]
impl InMemSignalProtocolStore {
    pub fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> PyResult<Option<SessionRecord>> {

        match self.store.load_session(&address.state, None).unwrap() {
            None => Ok(None),
            Some(session) => Ok(Some(SessionRecord{state: session}))
            }
    }

    fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> PyResult<()> {
        match self.store.store_session(&address.state, &record.state, None) {
            Ok(result)  => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("could not store session"))
        }
    }
}

/// libsignal_protocol_rust::PreKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_pre_key(&self, id: PreKeyId) -> PyResult<PreKeyRecord> {
        match self.store.pre_key_store.get_pre_key(id, None) {
            Ok(result)  => Ok(PreKeyRecord { state: result }),
            Err(_e) => Err(SignalProtocolError::new_err("invalid prekey ID"))
        }
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> PyResult<()> {
        match self.store.pre_key_store.save_pre_key(id, &record.state, None) {
            Ok(result)  => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("unknown signal error"))
        }
    }

    // fn remove_pre_key(&mut self, id: PreKeyId, ctx: Context) -> Result<()> {
    //     self.pre_key_store.remove_pre_key(id, ctx)
    // }
}

/// libsignal_protocol_rust::SignedPreKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    // fn get_signed_pre_key(&self, id: SignedPreKeyId, _ctx: Context) -> Result<SignedPreKeyRecord> {
    //     Ok(self
    //         .signed_pre_keys
    //         .get(&id)
    //         .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?
    //         .clone())
    // }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> PyResult<()> {
        match self.store.save_signed_pre_key(id, &record.state.to_owned(), None) {
            Ok(_result)  => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not save signed prekey"))
        }
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<InMemSignalProtocolStore>()?;
    Ok(())
}
