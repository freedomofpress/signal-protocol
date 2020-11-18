use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

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
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not create InMemSignalProtocolStore",
            )),
        }
    }
}

/// libsignal_protocol_rust::IdentityKeyStore
/// is_trusted_identity is not implemented (it requries traits::Direction as arg)
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_identity_key_pair(&self) -> PyResult<IdentityKeyPair> {
        match self.store.identity_store.get_identity_key_pair(None) {
            Ok(key) => Ok(IdentityKeyPair { key }),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not get identity key pair",
            )),
        }
    }

    fn get_local_registration_id(&self) -> PyResult<u32> {
        match self.store.identity_store.get_local_registration_id(None) {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not get local registration ID",
            )),
        }
    }

    fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> PyResult<bool> {
        match self
            .store
            .identity_store
            .save_identity(&address.state, &identity.key, None)
        {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("could not save identity")),
        }
    }

    fn get_identity(&self, address: &ProtocolAddress) -> PyResult<Option<IdentityKey>> {
        let key = match self.store.identity_store.get_identity(&address.state, None) {
            Ok(key) => key,
            Err(_e) => return Err(SignalProtocolError::new_err("could not get identity")),
        };

        match key {
            Some(key) => Ok(Some(IdentityKey { key })),
            None => Ok(None),
        }
    }
}

/// libsignal_protocol_rust::SessionStore
#[pymethods]
impl InMemSignalProtocolStore {
    pub fn load_session(&self, address: &ProtocolAddress) -> PyResult<Option<SessionRecord>> {
        let session = match self.store.load_session(&address.state, None) {
            Ok(session) => session,
            Err(_e) => return Err(SignalProtocolError::new_err("could not load session")),
        };

        match session {
            None => Ok(None),
            Some(state) => Ok(Some(SessionRecord { state })),
        }
    }

    fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> PyResult<()> {
        match self
            .store
            .store_session(&address.state, &record.state, None)
        {
            Ok(()) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not store session")),
        }
    }
}

/// libsignal_protocol_rust::PreKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_pre_key(&self, id: PreKeyId) -> PyResult<PreKeyRecord> {
        match self.store.pre_key_store.get_pre_key(id, None) {
            Ok(result) => Ok(PreKeyRecord { state: result }),
            Err(_e) => Err(SignalProtocolError::new_err("invalid prekey ID")),
        }
    }

    fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> PyResult<()> {
        match self
            .store
            .pre_key_store
            .save_pre_key(id, &record.state, None)
        {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("unknown signal error")),
        }
    }

    fn remove_pre_key(&mut self, id: PreKeyId) -> PyResult<()> {
        match self.store.pre_key_store.remove_pre_key(id, None) {
            Ok(()) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not remove prekey")),
        }
    }
}

/// libsignal_protocol_rust::SignedPreKeyStore
#[pymethods]
impl InMemSignalProtocolStore {
    fn get_signed_pre_key(&self, id: SignedPreKeyId) -> PyResult<SignedPreKeyRecord> {
        match self.store.get_signed_pre_key(id, None) {
            Ok(state) => Ok(SignedPreKeyRecord { state }),
            Err(_e) => Err(SignalProtocolError::new_err("could not get signed prekey")),
        }
    }

    fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> PyResult<()> {
        match self
            .store
            .save_signed_pre_key(id, &record.state.to_owned(), None)
        {
            Ok(()) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not save signed prekey")),
        }
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
