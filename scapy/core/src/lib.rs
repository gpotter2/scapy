use pyo3::prelude::*;
use pyo3::wrap_pymodule;

mod types;
mod utils;

pub mod fields;
pub mod packet;

#[pymodule]
fn core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(fields::fields))?;
    m.add_wrapped(wrap_pymodule!(packet::packet))?;
    m.add_wrapped(wrap_pymodule!(types::types))?;
    Ok(())
}
