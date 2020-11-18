use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;
use std::convert;

use crate::address::ProtocolAddress;
use crate::error::SignalProtocolError;
use crate::identity_key::{IdentityKey, IdentityKeyPair};
use crate::state::{PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord};

use libsignal_protocol_rust;
// traits
use libsignal_protocol_rust::{IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore};

#[pyclass]
#[derive(Clone)]
pub struct InMemSignalProtocolStore {
    pub store: libsignal_protocol_rust::InMemSignalProtocolStore,
}

#[pymethods]
impl InMemSignalProtocolStore {
    #[new]
    fn new(key_pair: &IdentityKeyPair, registration_id: u32) -> PyResult<InMemSignalProtocolStore> {
        match libsignal_protocol_rust::InMemSignalProtocolStore::new(key_pair.key, registration_id)
        {
            Ok(store) => Ok(Self { store }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }
}

/// libsignal_protocol_rust::IdentityKeyStore
/// is_trusted_identity is not implemented (it requries traits::Direction as arg)
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let key = self.store.identity_store.get_identity_key_pair(None)?;
        Ok(IdentityKeyPair { key })
    }

    fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.store.identity_store.get_local_registration_id(None)?)
    }

    fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self
            .store
            .identity_store
            .save_identity(&address.state, &identity.key, None)?)
    }

    fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let key = self
            .store
            .identity_store
            .get_identity(&address.state, None)?;

        match key {
            Some(key) => Ok(Some(IdentityKey { key })),
            None => Ok(None),
        }
    }
}

/// libsignal_protocol_rust::SessionStore
#[pymethods]
impl InMemSignalProtocolStore {
    pub fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let session = self.store.load_session(&address.state, None)?;

        match session {
            None => Ok(None),
            Some(state) => Ok(Some(SessionRecord { state })),
        }
    }

    fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.store
            .store_session(&address.state, &record.state, None)?;
        Ok(())
    }
}

/// libsignal_protocol_rust::PreKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_pre_key(&self, id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let state = self.store.pre_key_store.get_pre_key(id, None)?;
        Ok(PreKeyRecord { state })
    }

    fn save_pre_key(
        &mut self,
        id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.store
            .pre_key_store
            .save_pre_key(id, &record.state, None)?;
        Ok(())
    }

    fn remove_pre_key(&mut self, id: PreKeyId) -> Result<(), SignalProtocolError> {
        self.store.pre_key_store.remove_pre_key(id, None)?;
        Ok(())
    }
}

/// libsignal_protocol_rust::SignedPreKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_signed_pre_key(
        &self,
        id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let state = self.store.get_signed_pre_key(id, None)?;
        Ok(SignedPreKeyRecord { state })
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.store
            .save_signed_pre_key(id, &record.state.to_owned(), None)?;
        Ok(())
    }
}

/// The storage traits are not exposed as part of the API (this is not supported by Pyo3)
///
/// Python classes for InMemSenderKeyStore, InMemSessionStore, InMemIdentityKeyStore, InMemPreKeyStore
/// or InMemSignedPreKeyStore are not exposed.
/// One will need to operate on the InMemSignalProtocolStore instead.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<InMemSignalProtocolStore>()?;
    Ok(())
}
