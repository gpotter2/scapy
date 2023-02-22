use pyo3::prelude::*;
use pyo3::wrap_pymodule;

mod fields;

#[pymodule]
fn core(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(fields::fields))?;
    Ok(())
}
