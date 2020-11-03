use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use libsignal_protocol_rust;

#[pyclass]
#[derive(Clone, Debug)]
pub struct ProtocolAddress {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    device_id: u32,
    pub state: libsignal_protocol_rust::ProtocolAddress,
}

#[pymethods]
impl ProtocolAddress {
    #[new]
    fn new(name: String, device_id: u32) -> ProtocolAddress {
        ProtocolAddress {
            name: name.clone(),
            device_id: device_id.clone(),
            state: libsignal_protocol_rust::ProtocolAddress::new(name, device_id),
        }
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<ProtocolAddress>()?;
    Ok(())
}
