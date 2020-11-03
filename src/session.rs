use pyo3::prelude::*;
use pyo3::pyclass::PyClassAlloc;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

use crate::address::ProtocolAddress;
use crate::state::PreKeyBundle;
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn process_prekey_bundle(
    remote_address: ProtocolAddress,
    protocol_store: &mut InMemSignalProtocolStore,
    bundle: PreKeyBundle,
) -> PyResult<()> {
    let mut csprng = OsRng;

    Ok(libsignal_protocol_rust::process_prekey_bundle(
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &bundle.state,
        &mut csprng,
        None,
    )
    .unwrap())
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(process_prekey_bundle))?;
    Ok(())
}
