use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use libsignal_protocol_rust;

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

        Ok(PreKeyBundle {
            state: libsignal_protocol_rust::PreKeyBundle::new(
                registration_id,
                device_id,
                pre_key_id,
                pre_key,
                signed_pre_key_id,
                signed_pre_key,
                signed_pre_key_signature,
                identity_key_direct,
            )
            .unwrap(),
        })
    }

    fn registration_id(&self) -> PyResult<u32> {
        match self.state.registration_id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access registration ID",
            )),
        }
    }

    fn device_id(&self) -> PyResult<u32> {
        match self.state.device_id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("could not access device ID")),
        }
    }

    fn pre_key_id(&self) -> PyResult<Option<PreKeyId>> {
        match self.state.pre_key_id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("could not access prekey ID")),
        }
    }

    fn pre_key_public(&self) -> PyResult<Option<PublicKey>> {
        let key = match self.state.pre_key_public() {
            Ok(key) => key,
            Err(_e) => {
                return Err(SignalProtocolError::new_err(
                    "could not access prekey public key",
                ))
            }
        };

        match key {
            Some(key) => Ok(Some(PublicKey { key })),
            None => Ok(None),
        }
    }

    fn signed_pre_key_id(&self) -> PyResult<SignedPreKeyId> {
        match self.state.signed_pre_key_id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access signed prekey ID",
            )),
        }
    }

    fn signed_pre_key_public(&self) -> PyResult<PublicKey> {
        match self.state.signed_pre_key_public() {
            Ok(key) => Ok(PublicKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access signed prekey public key",
            )),
        }
    }

    fn signed_pre_key_signature(&self, py: Python) -> PyResult<PyObject> {
        match self.state.signed_pre_key_signature() {
            Ok(result) => Ok(PyBytes::new(py, result).into()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access signed prekey sig",
            )),
        }
    }

    fn identity_key(&self) -> PyResult<IdentityKey> {
        match self.state.identity_key() {
            Ok(key) => Ok(IdentityKey { key: *key }),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access identity key",
            )),
        }
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
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not deserialize to PreKeyRecord",
            )),
        }
    }

    fn id(&self) -> PyResult<PreKeyId> {
        match self.state.id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("could not access ID")),
        }
    }

    fn key_pair(&self) -> PyResult<KeyPair> {
        match self.state.key_pair() {
            Ok(key) => Ok(KeyPair { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not access keypair")),
        }
    }

    fn public_key(&self) -> PyResult<PublicKey> {
        match self.state.public_key() {
            Ok(key) => Ok(PublicKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not access public key")),
        }
    }

    fn private_key(&self) -> PyResult<PrivateKey> {
        match self.state.private_key() {
            Ok(key) => Ok(PrivateKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not access private key")),
        }
    }

    fn serialize(&self, py: Python) -> PyResult<PyObject> {
        match self.state.serialize() {
            Ok(result) => Ok(PyBytes::new(py, &result).into()),
            Err(_e) => Err(SignalProtocolError::new_err("could not serialize")),
        }
    }
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
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not deserialize to SignedPreKeyRecord",
            )),
        }
    }

    fn id(&self) -> PyResult<SignedPreKeyId> {
        match self.state.id() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("could not access ID")),
        }
    }

    fn timestamp(&self) -> PyResult<u64> {
        match self.state.timestamp() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err("could not access timestamp")),
        }
    }

    fn signature(&self, py: Python) -> PyResult<PyObject> {
        match self.state.signature() {
            Ok(result) => Ok(PyBytes::new(py, &result).into()),
            Err(_e) => Err(SignalProtocolError::new_err("could not access signature")),
        }
    }

    fn key_pair(&self) -> PyResult<KeyPair> {
        match self.state.key_pair() {
            Ok(key) => Ok(KeyPair { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not access keypair")),
        }
    }

    fn public_key(&self) -> PyResult<PublicKey> {
        match self.state.public_key() {
            Ok(key) => Ok(PublicKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not access public key")),
        }
    }

    fn private_key(&self) -> PyResult<PrivateKey> {
        match self.state.private_key() {
            Ok(key) => Ok(PrivateKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not access private key")),
        }
    }

    fn serialize(&self, py: Python) -> PyResult<PyObject> {
        match self.state.serialize() {
            Ok(result) => Ok(PyBytes::new(py, &result).into()),
            Err(_e) => Err(SignalProtocolError::new_err("could not serialize")),
        }
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
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not deserialize to SessionState",
            )),
        }
    }

    pub fn session_version(&self) -> PyResult<u32> {
        match self.state.session_version() {
            Ok(version) => Ok(version),
            Err(_e) => Err(SignalProtocolError::new_err("unknown signal error")),
        }
    }

    pub fn alice_base_key(&self, py: Python) -> PyResult<PyObject> {
        match self.state.alice_base_key() {
            Ok(key) => Ok(PyBytes::new(py, key).into()),
            Err(_e) => Err(SignalProtocolError::new_err("cannot get base key")),
        }
    }

    pub fn set_alice_base_key(&mut self, key: &[u8]) -> PyResult<()> {
        match self.state.set_alice_base_key(key) {
            Ok(_) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("cannot set base key")),
        }
    }

    fn remote_identity_key(&self) -> PyResult<Option<IdentityKey>> {
        let key = match self.state.remote_identity_key() {
            Ok(key) => key,
            Err(_e) => {
                return Err(SignalProtocolError::new_err(
                    "could not access remote identity key",
                ))
            }
        };

        match key {
            Some(key) => Ok(Some(IdentityKey { key })),
            None => Ok(None),
        }
    }

    fn local_identity_key(&self) -> PyResult<IdentityKey> {
        match self.state.local_identity_key() {
            Ok(key) => Ok(IdentityKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access local identity key",
            )),
        }
    }

    fn previous_counter(&self) -> PyResult<u32> {
        match self.state.previous_counter() {
            Ok(counter) => Ok(counter),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access previous counter",
            )),
        }
    }

    fn set_previous_counter(&mut self, counter: u32) -> PyResult<()> {
        match self.state.set_previous_counter(counter) {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not set previous counter",
            )),
        }
    }

    fn root_key(&self) -> PyResult<RootKey> {
        match self.state.root_key() {
            Ok(key) => Ok(RootKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not get root key")),
        }
    }

    fn set_root_key(&mut self, root_key: &RootKey) -> PyResult<()> {
        match self.state.set_root_key(&root_key.key) {
            Ok(key) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not set root key")),
        }
    }

    fn sender_ratchet_key(&self) -> PyResult<PublicKey> {
        match self.state.sender_ratchet_key() {
            Ok(key) => Ok(PublicKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not get pub key")),
        }
    }

    fn sender_ratchet_private_key(&self) -> PyResult<PrivateKey> {
        match self.state.sender_ratchet_private_key() {
            Ok(key) => Ok(PrivateKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not get priv key")),
        }
    }

    fn has_receiver_chain(&self, sender: &PublicKey) -> PyResult<bool> {
        match self.state.has_receiver_chain(&sender.key) {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not check receiver chain status",
            )),
        }
    }

    fn has_sender_chain(&self) -> PyResult<bool> {
        match self.state.has_sender_chain() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not check receiver chain status",
            )),
        }
    }

    fn get_receiver_chain_key(&self, sender: &PublicKey) -> PyResult<Option<ChainKey>> {
        let key = match self.state.get_receiver_chain_key(&sender.key) {
            Ok(key) => key,
            Err(_e) => {
                return Err(SignalProtocolError::new_err(
                    "could not get receiver chain key",
                ))
            }
        };

        match key {
            None => Ok(None),
            Some(key) => Ok(Some(ChainKey { key })),
        }
    }

    fn add_receiver_chain(&mut self, sender: &PublicKey, chain_key: &ChainKey) -> PyResult<()> {
        match self.state.add_receiver_chain(&sender.key, &chain_key.key) {
            Ok(_v) => Ok(()),
            Err(_e) => return Err(SignalProtocolError::new_err("could not add receiver chain")),
        }
    }

    fn set_sender_chain(&mut self, sender: &KeyPair, next_chain_key: &ChainKey) -> PyResult<()> {
        match self
            .state
            .set_sender_chain(&sender.key, &next_chain_key.key)
        {
            Ok(_v) => Ok(()),
            Err(_e) => return Err(SignalProtocolError::new_err("could not set sender chain")),
        }
    }

    fn get_sender_chain_key(&self) -> PyResult<ChainKey> {
        match self.state.get_sender_chain_key() {
            Ok(key) => Ok(ChainKey { key }),
            Err(_e) => Err(SignalProtocolError::new_err("could not get sender chain")),
        }
    }

    fn set_sender_chain_key(&mut self, next_chain_key: &ChainKey) -> PyResult<()> {
        match self.state.set_sender_chain_key(&next_chain_key.key) {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not set sender chain")),
        }
    }

    fn get_message_keys(
        &mut self,
        sender: &PublicKey,
        counter: u32,
    ) -> PyResult<Option<MessageKeys>> {
        let key = match self.state.get_message_keys(&sender.key, counter) {
            Ok(key) => key,
            Err(_e) => return Err(SignalProtocolError::new_err("could not get message keys")),
        };

        match key {
            Some(key) => Ok(Some(MessageKeys { key })),
            None => Ok(None),
        }
    }

    fn set_message_keys(&mut self, sender: &PublicKey, message_keys: &MessageKeys) -> PyResult<()> {
        match self.state.set_message_keys(&sender.key, &message_keys.key) {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not set message keys")),
        }
    }

    fn set_receiver_chain_key(&mut self, sender: &PublicKey, chain_key: &ChainKey) -> PyResult<()> {
        match self
            .state
            .set_receiver_chain_key(&sender.key, &chain_key.key)
        {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not set receiver chain key",
            )),
        }
    }

    fn set_pending_key_exchange(
        &mut self,
        sequence: u32,
        base_key: &KeyPair,
        ephemeral_key: &KeyPair,
        identity_key: &IdentityKeyPair,
    ) -> PyResult<()> {
        match self.state.set_pending_key_exchange(
            sequence,
            &base_key.key,
            &ephemeral_key.key,
            &identity_key.key,
        ) {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not set pending key exchange",
            )),
        }
    }

    fn pending_key_exchange_sequence(&self) -> PyResult<u32> {
        match self.state.pending_key_exchange_sequence() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not get pending key exchange",
            )),
        }
    }

    fn pending_key_exchange_base_key(&self) -> PyResult<KeyPair> {
        match self.state.pending_key_exchange_base_key() {
            Ok(key) => Ok(KeyPair { key }),
            Err(_e) => Err(SignalProtocolError::new_err("no pending key exchange")),
        }
    }

    fn pending_key_exchange_ratchet_key(&self) -> PyResult<KeyPair> {
        match self.state.pending_key_exchange_ratchet_key() {
            Ok(key) => Ok(KeyPair { key }),
            Err(_e) => Err(SignalProtocolError::new_err("no pending key exchange")),
        }
    }

    fn pending_key_exchange_identity_key(&self) -> PyResult<IdentityKeyPair> {
        match self.state.pending_key_exchange_identity_key() {
            Ok(key) => Ok(IdentityKeyPair { key }),
            Err(_e) => Err(SignalProtocolError::new_err("no pending key exchange")),
        }
    }

    fn has_pending_key_exchange(&self) -> PyResult<bool> {
        match self.state.has_pending_key_exchange() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not check for pending key exchange",
            )),
        }
    }

    fn set_unacknowledged_pre_key_message(
        &mut self,
        pre_key_id: Option<u32>,
        signed_pre_key_id: u32,
        base_key: &PublicKey,
    ) -> PyResult<()> {
        match self.state.set_unacknowledged_pre_key_message(
            pre_key_id,
            signed_pre_key_id,
            &base_key.key,
        ) {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not set unacknowledged pre key message",
            )),
        }
    }

    fn clear_unacknowledged_pre_key_message(&mut self) -> PyResult<()> {
        match self.state.clear_unacknowledged_pre_key_message() {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not clear unacknowledged pre key message",
            )),
        }
    }

    fn set_remote_registration_id(&mut self, registration_id: u32) -> PyResult<()> {
        match self.state.set_remote_registration_id(registration_id) {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not set remote registration id",
            )),
        }
    }

    fn remote_registration_id(&mut self) -> PyResult<u32> {
        match self.state.remote_registration_id() {
            Ok(id) => Ok(id),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not get remote registration id",
            )),
        }
    }

    fn set_local_registration_id(&mut self, registration_id: u32) -> PyResult<()> {
        match self.state.set_local_registration_id(registration_id) {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not set local registration id",
            )),
        }
    }

    fn local_registration_id(&mut self) -> PyResult<u32> {
        match self.state.local_registration_id() {
            Ok(id) => Ok(id),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not get local registration id",
            )),
        }
    }

    fn serialize(&mut self, py: Python) -> PyResult<PyObject> {
        match self.state.serialize() {
            Ok(result) => Ok(PyBytes::new(py, &result).into()),
            Err(_e) => Err(SignalProtocolError::new_err("could not serialize to bytes")),
        }
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

    fn session_state(&self) -> PyResult<SessionState> {
        match self.state.session_state() {
            Ok(state) => Ok(SessionState {
                state: state.clone(),
            }),
            Err(_e) => Err(SignalProtocolError::new_err("no session found")),
        }
    }

    #[staticmethod]
    fn deserialize(bytes: &[u8]) -> PyResult<Self> {
        match libsignal_protocol_rust::SessionRecord::deserialize(bytes) {
            Ok(state) => Ok(SessionRecord { state }),
            Err(_e) => Err(SignalProtocolError::new_err("could not deserialize")),
        }
    }

    fn has_session_state(&self, version: u32, alice_base_key: &[u8]) -> PyResult<bool> {
        match self.state.has_session_state(version, alice_base_key) {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not access session state",
            )),
        }
    }

    fn set_session_state(&mut self, session: SessionState) -> PyResult<()> {
        match self.state.set_session_state(session.state) {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not set session state")),
        }
    }

    fn promote_old_session(
        &mut self,
        old_session: usize,
        updated_session: SessionState,
    ) -> PyResult<()> {
        match self
            .state
            .promote_old_session(old_session, updated_session.state)
        {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not update session")),
        }
    }

    fn is_fresh(&self) -> PyResult<bool> {
        match self.state.is_fresh() {
            Ok(result) => Ok(result),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not check freshness of session",
            )),
        }
    }

    fn promote_state(&mut self, new_state: SessionState) -> PyResult<()> {
        match self.state.promote_state(new_state.state) {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err("could not promote state")),
        }
    }

    fn archive_current_state(&mut self) -> PyResult<()> {
        match self.state.archive_current_state() {
            Ok(_v) => Ok(()),
            Err(_e) => Err(SignalProtocolError::new_err(
                "could not archive current state",
            )),
        }
    }

    fn serialize(&self, py: Python) -> PyResult<PyObject> {
        match self.state.serialize() {
            Ok(result) => Ok(PyBytes::new(py, &result).into()),
            Err(_e) => Err(SignalProtocolError::new_err("could not serialize")),
        }
    }
}

/// UnacknowledgedPreKeyMessageItems is not exposed as part of the upstream public API.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<PreKeyBundle>()?;
    module.add_class::<PreKeyRecord>()?;
    module.add_class::<SessionRecord>()?;
    module.add_class::<SessionState>()?;
    module.add_class::<SignedPreKeyRecord>()?;
    Ok(())
}
