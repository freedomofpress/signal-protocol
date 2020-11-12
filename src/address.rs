use pyo3::prelude::*;
use pyo3::class::basic::PyObjectProtocol;

use libsignal_protocol_rust;

#[pyclass]
#[derive(Clone, Debug)]
pub struct ProtocolAddress {
    pub state: libsignal_protocol_rust::ProtocolAddress,
}

#[pymethods]
impl ProtocolAddress {
    #[new]
    fn new(name: String, device_id: u32) -> ProtocolAddress {
        ProtocolAddress {
            state: libsignal_protocol_rust::ProtocolAddress::new(name, device_id),
        }
    }

    pub fn name(&self) -> &str {
        &self.state.name()
    }

    pub fn device_id(&self) -> u32 {
        self.state.device_id()
    }
}

#[pyproto]
impl PyObjectProtocol for ProtocolAddress {
    fn __str__(&self) -> PyResult<String> {
        Ok(String::from(format!("{} {}", self.name(), self.device_id())))
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(String::from(format!("ProtocolAddress({}, {})", self.name(), self.device_id())))
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<ProtocolAddress>()?;
    Ok(())
}
