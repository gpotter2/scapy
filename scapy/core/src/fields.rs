use pyo3::prelude::*;

#[pyclass]
struct Field {
    name: str,
    fmt: str,
    default: u64,
    sz: u8,
}

#[pymodule]
pub fn fields(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<Field>()?;
    Ok(())
}
