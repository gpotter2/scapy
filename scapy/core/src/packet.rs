use pyo3::prelude::*;

/*
 * Packet is the rust equivalent of Scapy's main 'Packet' structure.
 * As definitions are done in Python, this is never really used directly.
 */
#[pyclass]
pub struct Packet {}

#[pymethods]
impl Packet {
    #[new]
    pub fn new(data: Option<&[u8]>) -> Self {
        Packet {}
    }
}

#[pymodule]
pub fn packet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Packet>()?;
    Ok(())
}
