use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use libsignal_protocol_rust;
use libsignal_protocol_rust::{IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore};

use crate::address::ProtocolAddress;
use crate::error::SignalProtocolError;
use crate::protocol::PreKeySignalMessage;
use crate::state::{PreKeyBundle, PreKeyId, SessionRecord};
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn process_prekey(
    message: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_record: &mut SessionRecord,
    protocol_store: &mut InMemSignalProtocolStore,
) -> Result<Option<PreKeyId>, SignalProtocolError> {
    let result = libsignal_protocol_rust::process_prekey(
        &message.data,
        &remote_address.state,
        &mut session_record.state,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        None,
    )?;
    Ok(result)
}

#[pyfunction]
pub fn process_prekey_bundle(
    remote_address: ProtocolAddress,
    protocol_store: &mut InMemSignalProtocolStore,
    bundle: PreKeyBundle,
) -> Result<(), SignalProtocolError> {
    let mut csprng = OsRng;
    let result = libsignal_protocol_rust::process_prekey_bundle(
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &bundle.state,
        &mut csprng,
        None,
    )?;
    Ok(())
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(process_prekey_bundle))?;
    module.add_wrapped(wrap_pyfunction!(process_prekey))?;
    Ok(())
}
