
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod curve;

/// Signal Protocol in Python
///
/// This Rust extension provides Python bindings for the Rust crate
/// libsignal-protocol-rust.
///
/// Basic usage:
///
/// >>> pub, priv = signal_protocol.generate_keypair()
///
#[pymodule]
fn signal_protocol(py: Python, module: &PyModule) -> PyResult<()> {
    let curve_submod = PyModule::new(py, "curve")?;
    curve::init_curve_submodule(curve_submod)?;
    module.add_submodule(curve_submod)?;

    Ok(())
}
