use pyo3::prelude::*;
use pyo3::create_exception;
use pyo3::exceptions::PyException;


create_exception!(signal_protocol, SignalProtocolError, PyException);


pub fn init_submodule(py: Python, module: &PyModule) -> PyResult<()> {
    module.add("SignalProtocolError", py.get_type::<SignalProtocolError>())?;
    Ok(())
}
