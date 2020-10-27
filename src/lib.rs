
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod address;
mod curve;

/// Signal Protocol in Python
///
/// This Rust extension provides Python bindings for the Rust crate
/// libsignal-protocol-rust.
///
/// Basic usage:
///
/// >>> pub, priv = signal_protocol.curve.generate_keypair()
///
#[pymodule]
fn signal_protocol(py: Python, module: &PyModule) -> PyResult<()> {
    let address_submod = PyModule::new(py, "address")?;
    address::init_submodule(address_submod)?;
    module.add_submodule(address_submod)?;

    let curve_submod = PyModule::new(py, "curve")?;
    curve::init_curve_submodule(curve_submod)?;
    module.add_submodule(curve_submod)?;

    Ok(())
}
