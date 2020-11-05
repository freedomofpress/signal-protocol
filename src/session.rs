use pyo3::prelude::*;
use pyo3::pyclass::PyClassAlloc;
use pyo3::wrap_pyfunction;
use pyo3::exceptions;
use pyo3::types::PyBytes;

use rand::rngs::OsRng;

use libsignal_protocol_rust;

use crate::address::ProtocolAddress;
use crate::error::SignalProtocolError;
use crate::state::PreKeyBundle;
use crate::storage::InMemSignalProtocolStore;


#[pyclass]
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub state: libsignal_protocol_rust::SessionRecord
}

/// Note: Many methods defined on SessionState are defined directly on SessionRecord
/// where it made sense instead. This is because a SessionState adapter object cannot
/// take ownership of libsignal_protocol_rust::SessionState,
/// and libsignal_protocol_rust::SessionState does not implement Copy.
/// Lifetime annotations would be required to keep a reference, which we can't do in PyO3.
#[pymethods]
impl SessionRecord {
    #[staticmethod]
    pub fn new_fresh() -> Self {
        SessionRecord{ state: libsignal_protocol_rust::SessionRecord::new_fresh() }
    }

    // TODO: Extract useful err info from within SignalProtocolError? using its fmt::Display impl
    pub fn session_version(&self) -> PyResult<u32> {
        let session_state = self.state.session_state();

        match session_state {
            Ok(session_state) => (),
            Err(_e) => return Err(SignalProtocolError::new_err("no session found"))
        };

        match session_state.unwrap().session_version() {
            Ok(version)  => Ok(version),
            Err(_e) => Err(SignalProtocolError::new_err("unknown signal error"))
        }
    }

    pub fn alice_base_key(&self, py: Python) -> PyResult<PyObject> {
        let session_state = self.state.session_state();

        match session_state {
            Ok(session_state) => (),
            Err(_e) => return Err(SignalProtocolError::new_err("no session found"))
        };

        match session_state.unwrap().alice_base_key() {
            Ok(key)  => Ok(PyBytes::new(py, key).into()),
            Err(_e) => Err(SignalProtocolError::new_err("cannot get base key"))
        }
    }
}

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
    module.add_class::<SessionRecord>()?;
    module.add_wrapped(wrap_pyfunction!(process_prekey_bundle))?;
    Ok(())
}
