use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use crate::curve::{KeyPair, PrivateKey, PublicKey};
use crate::error::SignalProtocolError;
use crate::identity_key::{IdentityKey, IdentityKeyPair};
use crate::ratchet::{ChainKey, MessageKeys, RootKey};

// Newtypes from upstream crate not exposed as part of the public API
pub type SignedPreKeyId = u32;
pub type PreKeyId = u32;

#[pyclass]
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    pub state: libsignal_protocol_rust::PreKeyBundle,
}

#[pymethods]
impl PreKeyBundle {
    #[new]
    fn new(
        registration_id: u32,
        device_id: u32,
        pre_key_id: Option<PreKeyId>,
        pre_key_public: Option<PublicKey>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: Vec<u8>,
        identity_key: IdentityKey,
    ) -> PyResult<Self> {
        let pre_key: std::option::Option<libsignal_protocol_rust::PublicKey> = match pre_key_public
        {
            Some(inner) => Some(inner.key),
            None => None,
        };

        let signed_pre_key = signed_pre_key_public.key;
        let identity_key_direct = identity_key.key;

        match libsignal_protocol_rust::PreKeyBundle::new(
            registration_id,
            device_id,
            pre_key_id,
            pre_key,
            signed_pre_key_id,
            signed_pre_key,
            signed_pre_key_signature,
            identity_key_direct,
        ) {
            Ok(state) => Ok(PreKeyBundle { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.registration_id()?)
    }

    fn device_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.device_id()?)
    }

    fn pre_key_id(&self) -> Result<Option<PreKeyId>, SignalProtocolError> {
        Ok(self.state.pre_key_id()?)
    }

    fn pre_key_public(&self) -> Result<Option<PublicKey>, SignalProtocolError> {
        let key = self.state.pre_key_public()?;
        match key {
            Some(key) => Ok(Some(PublicKey { key })),
            None => Ok(None),
        }
    }

    fn signed_pre_key_id(&self) -> Result<SignedPreKeyId, SignalProtocolError> {
        Ok(self.state.signed_pre_key_id()?)
    }

    fn signed_pre_key_public(&self) -> Result<PublicKey, SignalProtocolError> {
        Ok(PublicKey {
            key: self.state.signed_pre_key_public()?,
        })
    }

    fn signed_pre_key_signature(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.state.signed_pre_key_signature()?;
        Ok(PyBytes::new(py, result).into())
    }

    fn identity_key(&self) -> Result<IdentityKey, SignalProtocolError> {
        Ok(IdentityKey {
            key: *self.state.identity_key()?,
        })
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PreKeyRecord {
    pub state: libsignal_protocol_rust::PreKeyRecord,
}

#[pymethods]
impl PreKeyRecord {
    #[new]
    fn new(id: PreKeyId, keypair: &KeyPair) -> Self {
        let key =
            libsignal_protocol_rust::KeyPair::new(keypair.key.public_key, keypair.key.private_key);
        PreKeyRecord {
            state: libsignal_protocol_rust::PreKeyRecord::new(id, &key),
        }
    }

    #[staticmethod]
    fn deserialize(data: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::PreKeyRecord::deserialize(data) {
            Ok(state) => Ok(PreKeyRecord { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn id(&self) -> Result<PreKeyId, SignalProtocolError> {
        Ok(self.state.id()?)
    }

    fn key_pair(&self) -> Result<KeyPair, SignalProtocolError> {
        Ok(KeyPair {
            key: self.state.key_pair()?,
        })
    }

    fn public_key(&self) -> Result<PublicKey, SignalProtocolError> {
        Ok(PublicKey {
            key: self.state.public_key()?,
        })
    }

    fn private_key(&self) -> Result<PrivateKey, SignalProtocolError> {
        Ok(PrivateKey::new(self.state.private_key()?))
    }

    fn serialize(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.state.serialize()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

/// Helper function for generating N prekeys.
/// Returns a list of PreKeyRecords.
///
/// # Example
///
/// ```
/// from signal_protocol import curve, state
///
/// prekeyid = 1
/// manykeys = state.generate_n_prekeys(100, prekeyid)  # generates 100 keys
/// ```
#[pyfunction]
pub fn generate_n_prekeys(n: u16, id: PreKeyId) -> Vec<PreKeyRecord> {
    let mut keyvec: Vec<PreKeyRecord> = Vec::new();
    let mut i: u32 = id;
    for _n in 0..n {
        let keypair = KeyPair::generate();
        let prekey = PreKeyRecord::new(i, &keypair);
        keyvec.push(prekey);
        i += 1;
    }

    keyvec
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct SignedPreKeyRecord {
    pub state: libsignal_protocol_rust::SignedPreKeyRecord,
}

#[pymethods]
impl SignedPreKeyRecord {
    #[new]
    fn new(id: SignedPreKeyId, timestamp: u64, keypair: &KeyPair, signature: &[u8]) -> Self {
        let key =
            libsignal_protocol_rust::KeyPair::new(keypair.key.public_key, keypair.key.private_key);
        SignedPreKeyRecord {
            state: libsignal_protocol_rust::SignedPreKeyRecord::new(
                id, timestamp, &key, &signature,
            ),
        }
    }

    #[staticmethod]
    fn deserialize(data: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::SignedPreKeyRecord::deserialize(data) {
            Ok(state) => Ok(SignedPreKeyRecord { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn id(&self) -> Result<SignedPreKeyId, SignalProtocolError> {
        Ok(self.state.id()?)
    }

    fn timestamp(&self) -> Result<u64, SignalProtocolError> {
        Ok(self.state.timestamp()?)
    }

    fn signature(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let sig = self.state.signature()?;
        Ok(PyBytes::new(py, &sig).into())
    }

    fn key_pair(&self) -> Result<KeyPair, SignalProtocolError> {
        Ok(KeyPair {
            key: self.state.key_pair()?,
        })
    }

    fn public_key(&self) -> Result<PublicKey, SignalProtocolError> {
        Ok(PublicKey {
            key: self.state.public_key()?,
        })
    }

    fn private_key(&self) -> Result<PrivateKey, SignalProtocolError> {
        Ok(PrivateKey {
            key: self.state.private_key()?,
        })
    }

    fn serialize(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.state.serialize()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct SessionState {
    state: libsignal_protocol_rust::SessionState,
}

/// There is no new()/__init__ for SessionState, one must use the deserialize method
/// or use a SessionState struct returned from another method.
///
/// Other unimplemented methods on the Python API are:
/// * get_receiver_chain
/// * unacknowledged_pre_key_message_items (since return type is an upstream private struct)
/// * previous_session_states
#[pymethods]
impl SessionState {
    #[staticmethod]
    fn deserialize(data: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::SessionState::deserialize(data) {
            Ok(state) => Ok(SessionState { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn session_version(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.session_version()?)
    }

    pub fn alice_base_key(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let key = self.state.alice_base_key()?;
        Ok(PyBytes::new(py, key).into())
    }

    pub fn set_alice_base_key(&mut self, key: &[u8]) -> Result<(), SignalProtocolError> {
        self.state.set_alice_base_key(key)?;
        Ok(())
    }

    fn remote_identity_key(&self) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let key = self.state.remote_identity_key()?;
        match key {
            Some(key) => Ok(Some(IdentityKey { key })),
            None => Ok(None),
        }
    }

    fn local_identity_key(&self) -> Result<IdentityKey, SignalProtocolError> {
        Ok(IdentityKey {
            key: self.state.local_identity_key()?,
        })
    }

    fn previous_counter(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.previous_counter()?)
    }

    fn set_previous_counter(&mut self, counter: u32) -> Result<(), SignalProtocolError> {
        self.state.set_previous_counter(counter)?;
        Ok(())
    }

    fn root_key(&self) -> Result<RootKey, SignalProtocolError> {
        Ok(RootKey {
            key: self.state.root_key()?,
        })
    }

    fn set_root_key(&mut self, root_key: &RootKey) -> Result<(), SignalProtocolError> {
        self.state.set_root_key(&root_key.key)?;
        Ok(())
    }

    fn sender_ratchet_key(&self) -> Result<PublicKey, SignalProtocolError> {
        Ok(PublicKey {
            key: self.state.sender_ratchet_key()?,
        })
    }

    fn sender_ratchet_private_key(&self) -> Result<PrivateKey, SignalProtocolError> {
        Ok(PrivateKey {
            key: self.state.sender_ratchet_private_key()?,
        })
    }

    fn has_receiver_chain(&self, sender: &PublicKey) -> Result<bool, SignalProtocolError> {
        Ok(self.state.has_receiver_chain(&sender.key)?)
    }

    fn has_sender_chain(&self) -> Result<bool, SignalProtocolError> {
        Ok(self.state.has_sender_chain()?)
    }

    fn get_receiver_chain_key(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<ChainKey>, SignalProtocolError> {
        let key = self.state.get_receiver_chain_key(&sender.key)?;
        match key {
            None => Ok(None),
            Some(key) => Ok(Some(ChainKey { key })),
        }
    }

    fn add_receiver_chain(
        &mut self,
        sender: &PublicKey,
        chain_key: &ChainKey,
    ) -> Result<(), SignalProtocolError> {
        self.state.add_receiver_chain(&sender.key, &chain_key.key)?;
        Ok(())
    }

    fn set_sender_chain(
        &mut self,
        sender: &KeyPair,
        next_chain_key: &ChainKey,
    ) -> Result<(), SignalProtocolError> {
        self.state
            .set_sender_chain(&sender.key, &next_chain_key.key)?;
        Ok(())
    }

    fn get_sender_chain_key(&self) -> Result<ChainKey, SignalProtocolError> {
        Ok(ChainKey {
            key: self.state.get_sender_chain_key()?,
        })
    }

    fn set_sender_chain_key(
        &mut self,
        next_chain_key: &ChainKey,
    ) -> Result<(), SignalProtocolError> {
        self.state.set_sender_chain_key(&next_chain_key.key)?;
        Ok(())
    }

    fn get_message_keys(
        &mut self,
        sender: &PublicKey,
        counter: u32,
    ) -> Result<Option<MessageKeys>, SignalProtocolError> {
        let key = self.state.get_message_keys(&sender.key, counter)?;

        match key {
            Some(key) => Ok(Some(MessageKeys { key })),
            None => Ok(None),
        }
    }

    fn set_message_keys(
        &mut self,
        sender: &PublicKey,
        message_keys: &MessageKeys,
    ) -> Result<(), SignalProtocolError> {
        self.state
            .set_message_keys(&sender.key, &message_keys.key)?;
        Ok(())
    }

    fn set_receiver_chain_key(
        &mut self,
        sender: &PublicKey,
        chain_key: &ChainKey,
    ) -> Result<(), SignalProtocolError> {
        self.state
            .set_receiver_chain_key(&sender.key, &chain_key.key)?;
        Ok(())
    }

    fn set_pending_key_exchange(
        &mut self,
        sequence: u32,
        base_key: &KeyPair,
        ephemeral_key: &KeyPair,
        identity_key: &IdentityKeyPair,
    ) -> Result<(), SignalProtocolError> {
        self.state.set_pending_key_exchange(
            sequence,
            &base_key.key,
            &ephemeral_key.key,
            &identity_key.key,
        )?;
        Ok(())
    }

    fn pending_key_exchange_sequence(&self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.pending_key_exchange_sequence()?)
    }

    fn pending_key_exchange_base_key(&self) -> Result<KeyPair, SignalProtocolError> {
        Ok(KeyPair {
            key: self.state.pending_key_exchange_base_key()?,
        })
    }

    fn pending_key_exchange_ratchet_key(&self) -> Result<KeyPair, SignalProtocolError> {
        Ok(KeyPair {
            key: self.state.pending_key_exchange_ratchet_key()?,
        })
    }

    fn pending_key_exchange_identity_key(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        Ok(IdentityKeyPair {
            key: self.state.pending_key_exchange_identity_key()?,
        })
    }

    fn has_pending_key_exchange(&self) -> Result<bool, SignalProtocolError> {
        Ok(self.state.has_pending_key_exchange()?)
    }

    fn set_unacknowledged_pre_key_message(
        &mut self,
        pre_key_id: Option<u32>,
        signed_pre_key_id: u32,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        self.state.set_unacknowledged_pre_key_message(
            pre_key_id,
            signed_pre_key_id,
            &base_key.key,
        )?;
        Ok(())
    }

    fn clear_unacknowledged_pre_key_message(&mut self) -> Result<(), SignalProtocolError> {
        self.state.clear_unacknowledged_pre_key_message()?;
        Ok(())
    }

    fn set_remote_registration_id(
        &mut self,
        registration_id: u32,
    ) -> Result<(), SignalProtocolError> {
        self.state.set_remote_registration_id(registration_id)?;
        Ok(())
    }

    fn remote_registration_id(&mut self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.remote_registration_id()?)
    }

    fn set_local_registration_id(
        &mut self,
        registration_id: u32,
    ) -> Result<(), SignalProtocolError> {
        self.state.set_local_registration_id(registration_id)?;
        Ok(())
    }

    fn local_registration_id(&mut self) -> Result<u32, SignalProtocolError> {
        Ok(self.state.local_registration_id()?)
    }

    fn serialize(&mut self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.state.serialize()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub state: libsignal_protocol_rust::SessionRecord,
}

impl SessionRecord {
    pub fn new(state: libsignal_protocol_rust::SessionState) -> Self {
        SessionRecord {
            state: libsignal_protocol_rust::SessionRecord::new(state),
        }
    }
}

/// session_state_mut() is not exposed as part of the Python API.
#[pymethods]
impl SessionRecord {
    #[staticmethod]
    pub fn new_fresh() -> Self {
        SessionRecord {
            state: libsignal_protocol_rust::SessionRecord::new_fresh(),
        }
    }

    fn session_state(&self) -> Result<SessionState, SignalProtocolError> {
        let state = self.state.session_state()?;
        Ok(SessionState {
            state: state.clone(),
        })
    }

    #[staticmethod]
    fn deserialize(bytes: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::SessionRecord::deserialize(bytes) {
            Ok(state) => Ok(SessionRecord { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn has_session_state(
        &self,
        version: u32,
        alice_base_key: &[u8],
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.state.has_session_state(version, alice_base_key)?)
    }

    fn set_session_state(&mut self, session: SessionState) -> Result<(), SignalProtocolError> {
        self.state.set_session_state(session.state)?;
        Ok(())
    }

    fn promote_old_session(
        &mut self,
        old_session: usize,
        updated_session: SessionState,
    ) -> Result<(), SignalProtocolError> {
        self.state
            .promote_old_session(old_session, updated_session.state)?;
        Ok(())
    }

    fn is_fresh(&self) -> Result<bool, SignalProtocolError> {
        Ok(self.state.is_fresh()?)
    }

    fn promote_state(&mut self, new_state: SessionState) -> Result<(), SignalProtocolError> {
        self.state.promote_state(new_state.state)?;
        Ok(())
    }

    fn archive_current_state(&mut self) -> Result<(), SignalProtocolError> {
        self.state.archive_current_state()?;
        Ok(())
    }

    fn serialize(&self, py: Python) -> Result<PyObject, SignalProtocolError> {
        let result = self.state.serialize()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

/// UnacknowledgedPreKeyMessageItems is not exposed as part of the upstream public API.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<PreKeyBundle>()?;
    module.add_class::<PreKeyRecord>()?;
    module.add_class::<SessionRecord>()?;
    module.add_class::<SessionState>()?;
    module.add_class::<SignedPreKeyRecord>()?;
    module.add_function(wrap_pyfunction!(generate_n_prekeys, module)?).unwrap();
    Ok(())
}
