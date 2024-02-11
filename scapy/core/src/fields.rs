use pyo3::prelude::*;

use crate::packet;

pub trait FieldTrait {
    type I;  // Internal
    type M;  // Machine

    // Box<[u8]> is used when dissecting
    // Vec<u8> is used when building
    fn new(name: String, default: Self::I) -> Self;
    fn m2i(&self, pkt: &mut packet::Packet, x: Self::M) -> Result<Self::I, PyErr>;
    fn i2m(&self, pkt: &mut packet::Packet, x: Option<Self::I>) -> Result<Self::M, PyErr>;
    // fn addfield(&self, pkt: packet::Packet, s: Vec<u8>, val: I) -> Result<Vec<u8>, PyErr>;
    // fn getfield(&self, pkt: packet::Packet, x: Box<[u8]>) -> Result<(I, Box<[u8]>), PyErr>;
}


macro_rules! Field {
    ( $pyname:ident, $i:ty, $m:ty ) => {
        #[pyclass]
        struct $pyname {
            name: String,
            default: $i,
            sz: usize,
        }

        impl FieldTrait for $pyname {
            type I = $i;
            type M = $m;

            fn new(name: String, default: Self::I) -> Self {
                $pyname {
                    name: name,
                    default: default,
                    sz: std::mem::size_of::<Self::I>()
                }
            }
            fn m2i(&self, _: &mut packet::Packet, x: Self::M) -> Result<Self::I, PyErr> {
                Ok(x)
            }
            fn i2m(&self, _: &mut packet::Packet, x: Option<Self::I>) -> Result<Self::M, PyErr> {
                if let Some(val) = x {
                    Ok(val)
                } else {
                    Ok(0)
                }
            }
        }

        // https://pyo3.rs/v0.20.2/trait_bounds#implementation-of-the-trait-bounds-for-the-python-class
        #[pymethods]
        impl $pyname {
            #[new]
            pub fn new(name: String, default: $i) -> Self {
                FieldTrait::new(name, default)
            }
            fn m2i(&self, pkt: &mut packet::Packet, x: $m) -> Result<$i, PyErr> {
                FieldTrait::m2i(self, pkt, x)
            }
            fn i2m(&self, pkt: &mut packet::Packet, x: Option<$i>) -> Result<$m, PyErr> {
                FieldTrait::i2m(self, pkt, x)
            }
        }
    };
}

Field![ByteField, u8, u8];
Field![ShortField, u16, u16];
Field![IntField, u32, u32];
Field![LongField, u64, u64];

#[pymodule]
pub fn fields(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<ByteField>()?;
    m.add_class::<ShortField>()?;
    m.add_class::<IntField>()?;
    m.add_class::<LongField>()?;
    Ok(())
}
