use pyo3::create_exception;
use pyo3::prelude::*;
use pyo3::PyErr;

use std::{convert, fmt};

create_exception!(
    error,
    SignalProtocolException,
    pyo3::exceptions::PyException
);

#[pyclass]
pub struct SignalProtocolError {
    pub err: libsignal_protocol_rust::SignalProtocolError,
}

impl fmt::Display for SignalProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.err.to_string())
    }
}

impl convert::From<SignalProtocolError> for PyErr {
    fn from(err: SignalProtocolError) -> Self {
        SignalProtocolException::new_err(err.to_string())
    }
}

impl convert::From<libsignal_protocol_rust::SignalProtocolError> for SignalProtocolError {
    fn from(err: libsignal_protocol_rust::SignalProtocolError) -> Self {
        SignalProtocolError { err }
    }
}

impl SignalProtocolError {
    pub fn new(err: libsignal_protocol_rust::SignalProtocolError) -> Self {
        Self { err }
    }

    pub fn err_from_str(err: String) -> PyErr {
        SignalProtocolException::new_err(err)
    }

    pub fn new_err(err: libsignal_protocol_rust::SignalProtocolError) -> PyErr {
        let local_error = SignalProtocolError { err };
        SignalProtocolException::new_err(local_error.to_string())
    }
}

pub fn init_submodule(py: Python, module: &PyModule) -> PyResult<()> {
    module.add(
        "SignalProtocolException",
        py.get_type::<SignalProtocolException>(),
    )?;
    Ok(())
}
