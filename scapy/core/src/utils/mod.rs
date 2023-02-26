use pyo3::prelude::*;
use pyo3::wrap_pymodule;

pub mod r#struct;

#[pymodule]
pub fn utils(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(r#struct::r#struct))?;
    Ok(())
}
