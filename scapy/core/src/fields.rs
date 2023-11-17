use pyo3::prelude::*;

use crate::packet;

pub trait Field<I> {
    fn m2i(&self, pkt: packet::Packet, x: &[u8]) -> Result<I, &str>;
    fn i2m(&self, pkt: packet::Packet, x: &I) -> Result<&[u8], &str>;
    fn addfield(&self, pkt: packet::Packet, s: &[u8], val: &I) -> Result<&[u8], &str>;
    fn getfield(&self, pkt: packet::Packet, x: &[u8]) -> Result<I, &str>;
}

struct BasicField<I> {
    name: String,
    default: I,
    sz: usize,
}

#[pyclass(module = "scapy.core.fields")]
struct ByteField {

}

#[pymodule]
pub fn fields(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<ByteField>()?;
    Ok(())
}
