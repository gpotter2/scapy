use pyo3::prelude::*;

use crate::packet;
use crate::utils::r#struct::*;

pub trait FieldTrait<I, M> {
    // Box<[u8]> is used when dissecting
    // Vec<u8> is used when building
    fn new(&mut self, name: &'static str, default: I);
    fn m2i(&self, pkt: packet::Packet, x: M) -> Result<I, &str>;
    fn i2m(&self, pkt: packet::Packet, x: Option<I>) -> Result<M, &str>;
    // fn addfield(&self, pkt: packet::Packet, s: Vec<u8>, val: I) -> Result<Vec<u8>, &str>;
    // fn getfield(&self, pkt: packet::Packet, x: Box<[u8]>) -> Result<(I, Box<[u8]>), &str>;
}

struct Field {
    name: &'static str,
    default: StructValue,
    sz: u8,
}

impl FieldTrait<usize, usize> for Field {
    fn new(&mut self, name: &'static str, default: usize, fmt: &str) {
        self.name = name;
        self.default = default;
        self.sz = calcsize(fmt);
    }
    fn m2i(&self, _: packet::Packet, x: I) -> Result<I, &str> {
        Ok(x)
    }
    fn i2m(&self, _: packet::Packet, x: Option<I>) -> Result<I, &str> {
        if let Some(val) = x {
            Ok(val)
        } else {
            Ok(I::zero())
        }
    }
}

type ByteField = Field<u8>;

#[pymodule]
pub fn fields(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    //m.add_class::<ByteField>()?;
    Ok(())
}
