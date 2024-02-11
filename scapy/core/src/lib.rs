use pyo3::prelude::*;
use pyo3::wrap_pymodule;

pub mod fields;
pub mod packet;

#[pymodule]
fn core(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(fields::fields))?;
    m.add_wrapped(wrap_pymodule!(packet::packet))?;
    Ok(())
}
