use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use libsignal_protocol_rust;


#[pyclass]
pub struct ProtocolAddress {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    device_id: u32,
}

#[pymethods]
impl ProtocolAddress {
    #[new]
    fn new(name: String, device_id: u32) -> ProtocolAddress {
       ProtocolAddress{name, device_id}
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<ProtocolAddress>()?;
    Ok(())
}