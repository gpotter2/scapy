use pyo3::prelude::*;

use std::mem::size_of;

use num_traits::FromBytes;
use num_traits::ops::bytes::NumBytes;
use num_traits::int::PrimInt;

use crate::packet;

pub trait Field<I> {
    // Box<[u8]> is used when dissecting
    // Vec<u8> is used when building
    fn new(&mut self, name: &str, default: I);
    fn m2i(&self, pkt: packet::Packet, x: Box<[u8]>) -> Result<I, &str>;
    // fn i2m(&self, pkt: packet::Packet, x: I) -> Result<Vec<u8>, &str>;
    // fn addfield(&self, pkt: packet::Packet, s: Vec<u8>, val: I) -> Result<Vec<u8>, &str>;
    // fn getfield(&self, pkt: packet::Packet, x: Box<[u8]>) -> Result<(I, Box<[u8]>), &str>;
}

trait SimpleFieldType: PrimInt + FromBytes {}

struct SimpleField<I> {
    name: &'static str,
    default: I,
    sz: usize,
}

impl<I> Field<I> for SimpleField<I> where I: SimpleFieldType {
    fn new(&mut self, name: &str, default: I) {
        self.name = name;
        self.default = default;
    }
}

impl SimpleField<u8> {
    
}

pub struct ByteField SimpleField<u8> {};


#[pymodule]
pub fn fields(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<ByteField>()?;
    Ok(())
}
