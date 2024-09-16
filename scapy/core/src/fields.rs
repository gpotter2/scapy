use pyo3::prelude::*;

use crate::packet;
use crate::types;

/*
 * FieldTrait is the trait that must be implemented by all of Scapy's fields.
 */
pub trait FieldTrait {
    type I; // Internal
    type M: types::MachineType; // Machine

    // &[u8] is used when dissecting
    // Vec<u8> is used when building
    fn new(name: String, default: Self::I) -> Self
    where
        Self: Sized;
    fn m2i(&self, pkt: &packet::Packet, x: Self::M) -> Result<Self::I, PyErr>;
    fn i2m(&self, pkt: &packet::Packet, x: Option<Self::I>) -> Result<Self::M, PyErr>;
    fn addfield(
        &self,
        pkt: &packet::Packet,
        s: Vec<u8>,
        val: Option<Self::I>,
    ) -> Result<Vec<u8>, PyErr>;
    fn getfield<'a>(&self, pkt: &packet::Packet, x: &'a [u8])
        -> Result<(Self::I, &'a [u8]), PyErr>;
}

macro_rules! Field {
    /*
     * This Macro is used to implement the default Fields
     */
    ( $pyname:ident, $i:ty, $m:ty, $leendian:expr ) => {
        #[pyclass]
        #[derive(Clone)]
        pub struct $pyname {
            #[pyo3(get)]
            name: String,
            #[pyo3(get)]
            default: $i,
            #[pyo3(get)]
            sz: usize,
        }

        impl FieldTrait for $pyname {
            // https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#specifying-placeholder-types-in-trait-definitions-with-associated-types
            type I = $i;
            type M = $m;

            fn new(name: String, default: Self::I) -> Self {
                $pyname {
                    name: name,
                    default: default,
                    sz: std::mem::size_of::<Self::M>(),
                }
            }
            fn m2i(&self, _: &packet::Packet, x: Self::M) -> Result<Self::I, PyErr> {
                Ok(x)
            }
            fn i2m(&self, _: &packet::Packet, x: Option<Self::I>) -> Result<Self::M, PyErr> {
                if let Some(val) = x {
                    Ok(val)
                } else {
                    Ok(0)
                }
            }
            fn addfield(
                &self,
                pkt: &packet::Packet,
                mut s: Vec<u8>,
                val: Option<Self::I>,
            ) -> Result<Vec<u8>, PyErr> {
                if $leendian {
                    s.extend_from_slice(&self.i2m(pkt, val)?.to_le_bytes());
                } else {
                    s.extend_from_slice(&self.i2m(pkt, val)?.to_be_bytes());
                }
                Ok(s)
            }
            fn getfield<'a>(
                &self,
                pkt: &packet::Packet,
                x: &'a [u8],
            ) -> Result<(Self::I, &'a [u8]), PyErr> {
                Ok((
                    self.m2i(
                        pkt,
                        if $leendian {
                            Self::M::from_le_bytes(x[..self.sz].try_into()?)
                        } else {
                            Self::M::from_be_bytes(x[..self.sz].try_into()?)
                        },
                    )?,
                    &x[self.sz..],
                ))
            }
        }

        // https://pyo3.rs/v0.20.2/trait_bounds#implementation-of-the-trait-bounds-for-the-python-class
        #[pymethods]
        impl $pyname {
            #[new]
            pub fn new(name: String, default: $i) -> Self {
                FieldTrait::new(name, default)
            }
            fn m2i(&self, pkt: &packet::Packet, x: $m) -> Result<$i, PyErr> {
                FieldTrait::m2i(self, pkt, x)
            }
            #[pyo3(signature=(pkt, x=None))]
            fn i2m(&self, pkt: &packet::Packet, x: Option<$i>) -> Result<$m, PyErr> {
                FieldTrait::i2m(self, pkt, x)
            }
            #[pyo3(signature=(pkt, s, val=None))]
            fn addfield(
                &self,
                pkt: &packet::Packet,
                s: Vec<u8>,
                val: Option<$i>,
            ) -> Result<Vec<u8>, PyErr> {
                FieldTrait::addfield(self, pkt, s, val)
            }
            fn getfield<'a>(
                &self,
                pkt: &packet::Packet,
                x: &'a [u8],
            ) -> Result<($i, &'a [u8]), PyErr> {
                FieldTrait::getfield(self, pkt, x)
            }
        }
    };
}

Field![ByteField, u8, u8, false];
Field![ShortField, u16, u16, false];
Field![IntField, u32, u32, false];
Field![LongField, u64, u64, false];

Field![LEShortField, u16, u16, true];
Field![LEIntField, u32, u32, true];
Field![LELongField, u64, u64, true];

Field![SignedByteField, i8, i8, false];
Field![SignedShortField, i16, i16, false];
Field![SignedIntField, i32, i32, false];
Field![SignedLongField, i64, i64, false];

Field![LESignedShortField, i16, i16, true];
Field![LESignedIntField, i32, i32, true];
Field![LESignedLongField, i64, i64, true];

#[derive(FromPyObject, Clone)]
pub enum FieldType {
    ByteField(ByteField),
    ShortField(ShortField),
    IntField(IntField),
    LongField(LongField),
    LEShortField(LEShortField),
    LEIntField(LEIntField),
    LELongField(LELongField),
    SignedByteField(SignedByteField),
    SignedShortField(SignedShortField),
    SignedIntField(SignedIntField),
    SignedLongField(SignedLongField),
    LESignedShortField(LESignedShortField),
    LESignedIntField(LESignedIntField),
    LESignedLongField(LESignedLongField),
}

#[pymodule]
pub fn fields(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ByteField>()?;
    m.add_class::<ShortField>()?;
    m.add_class::<IntField>()?;
    m.add_class::<LongField>()?;
    m.add_class::<LEShortField>()?;
    m.add_class::<LEIntField>()?;
    m.add_class::<LELongField>()?;
    m.add_class::<SignedByteField>()?;
    m.add_class::<SignedShortField>()?;
    m.add_class::<SignedIntField>()?;
    m.add_class::<SignedLongField>()?;
    m.add_class::<LESignedShortField>()?;
    m.add_class::<LESignedIntField>()?;
    m.add_class::<LESignedLongField>()?;
    Ok(())
}
