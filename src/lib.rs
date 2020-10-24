use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use hello_world::hello;

#[pyfunction]
fn hi_hello() -> PyResult<()> {
    hello();
    Ok(())
}

#[pymodule]
fn signal_protocol(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(hi_hello))?;
    Ok(())
}
