use pyo3::prelude::*;

#[pyclass]
pub struct Packet {
    
}

#[pymodule]
pub fn packet(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<Packet>()?;
    Ok(())
}
