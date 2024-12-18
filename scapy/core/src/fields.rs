use std::collections::HashMap;

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;

use crate::packet;
use crate::types;

/*
 * FieldTrait is the common trait that defines the behavior of Fields.
 */

pub trait FieldTrait {
    // &[u8] is used when dissecting
    // Vec<u8> is used when building
    fn init(&mut self, kwargs: Option<HashMap<String, types::InternalType>>) -> PyResult<()>;
    fn any2i<'py>(
        &self,
        pkt: Option<&packet::Packet>,
        x: &Bound<'py, PyAny>,
    ) -> Result<types::InternalType, PyErr>;
    fn m2i(
        &self,
        pkt: &packet::Packet,
        x: types::MachineType,
    ) -> Result<types::InternalType, PyErr>;
    fn i2m(
        &self,
        pkt: &packet::Packet,
        x: Option<types::InternalType>,
    ) -> Result<types::MachineType, PyErr>;
    fn addfield(
        &self,
        pkt: &packet::Packet,
        s: Vec<u8>,
        val: Option<types::InternalType>,
    ) -> Result<Vec<u8>, PyErr>;
    fn getfield<'a>(
        &self,
        pkt: &packet::Packet,
        x: &'a [u8],
    ) -> Result<(types::InternalType, &'a [u8]), PyErr>;
}

// Standard fields

macro_rules! Field {
    ($pyname:ident, $i:ident, $m:ty, $leendian:expr) => {
        #[pyclass]
        #[derive(Clone)]
        pub struct $pyname {
            sz: usize,
        }

        // Define trait
        impl FieldTrait for $pyname {
            // https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#specifying-placeholder-types-in-trait-definitions-with-associated-types
            fn init(&mut self, _: Option<HashMap<String, types::InternalType>>) -> PyResult<()> {
                self.sz = std::mem::size_of::<$m>();
                Ok(())
            }
            fn any2i<'py>(
                &self,
                _: Option<&packet::Packet>,
                x: &Bound<'py, PyAny>,
            ) -> Result<types::InternalType, PyErr> {
                Ok(types::InternalType::$i(x.extract()?))
            }
            fn m2i(
                &self,
                _: &packet::Packet,
                x: types::MachineType,
            ) -> Result<types::InternalType, PyErr> {
                Ok(x.as_internal())
            }
            fn i2m(
                &self,
                _: &packet::Packet,
                x: Option<types::InternalType>,
            ) -> Result<types::MachineType, PyErr> {
                if let Some(val) = x {
                    Ok(val.as_machine())
                } else {
                    Ok(types::InternalType::$i(0).as_machine())
                }
            }
            fn addfield(
                &self,
                pkt: &packet::Packet,
                mut s: Vec<u8>,
                val: Option<types::InternalType>,
            ) -> Result<Vec<u8>, PyErr> {
                let mval = self.i2m(pkt, val)?;
                match mval {
                    types::MachineType::$i(x) => {
                        if $leendian {
                            s.extend_from_slice(&x.to_le_bytes());
                        } else {
                            s.extend_from_slice(&x.to_be_bytes());
                        };
                        return Ok(s);
                    }
                    _ => Err(PyTypeError::new_err("Bad type !")),
                }
            }
            fn getfield<'a>(
                &self,
                pkt: &packet::Packet,
                x: &'a [u8],
            ) -> Result<(types::InternalType, &'a [u8]), PyErr> {
                Ok((
                    self.m2i(
                        pkt,
                        if $leendian {
                            types::MachineType::$i(<$m>::from_le_bytes(x[..self.sz].try_into()?))
                        } else {
                            types::MachineType::$i(<$m>::from_be_bytes(x[..self.sz].try_into()?))
                        },
                    )?,
                    &x[self.sz..],
                ))
            }
        }

        // Define python aliases
        // https://pyo3.rs/v0.20.2/trait_bounds#implementation-of-the-trait-bounds-for-the-python-class
        #[pymethods]
        impl $pyname {
            #[pyo3(signature = (name, default, **kwargs))]
            #[staticmethod]
            pub fn new<'py>(
                name: String,
                default: &Bound<'py, PyAny>,
                kwargs: Option<HashMap<String, types::InternalType>>,
            ) -> PyResult<FieldProxy> {
                let mut x = $pyname { sz: 0 };
                x.init(kwargs)?;
                Ok(FieldProxy {
                    name: name,
                    default: types::InternalType::$i(default.extract()?),
                    sz: x.sz,
                    fieldtype: FieldType::$pyname(x),
                })
            }
            pub fn m2i(
                &self,
                pkt: &packet::Packet,
                x: types::MachineType,
            ) -> Result<types::InternalType, PyErr> {
                FieldTrait::m2i(self, pkt, x)
            }
            #[pyo3(signature=(pkt, x=None))]
            pub fn i2m(
                &self,
                pkt: &packet::Packet,
                x: Option<types::InternalType>,
            ) -> Result<types::MachineType, PyErr> {
                FieldTrait::i2m(self, pkt, x)
            }
            #[pyo3(signature=(pkt, s, val=None))]
            pub fn addfield(
                &self,
                pkt: &packet::Packet,
                s: Vec<u8>,
                val: Option<types::InternalType>,
            ) -> Result<Vec<u8>, PyErr> {
                FieldTrait::addfield(self, pkt, s, val)
            }
            pub fn getfield<'a>(
                &self,
                pkt: &packet::Packet,
                x: &'a [u8],
            ) -> Result<(types::InternalType, &'a [u8]), PyErr> {
                FieldTrait::getfield(self, pkt, x)
            }
        }
    };
}

Field![ByteField, Byte, u8, false];
Field![ShortField, Short, u16, false];
Field![IntField, Int, u32, false];
Field![LongField, Long, u64, false];
Field![LEShortField, Short, u16, true];
Field![LEIntField, Int, u32, true];
Field![LELongField, Long, u64, true];
Field![SignedByteField, SignedByte, i8, false];
Field![SignedShortField, SignedShort, i16, false];
Field![SignedIntField, SignedInt, i32, false];
Field![SignedLongField, SignedLong, i64, false];
Field![LESignedShortField, SignedShort, i16, true];
Field![LESignedIntField, SignedInt, i32, true];
Field![LESignedLongField, SignedLong, i64, true];

// String fields

macro_rules! _StrField {
    ($pyname:ident) => {
        #[pyclass]
        #[derive(Clone)]
        pub struct $pyname {
            sz: usize,
            remain: usize,
        }

        // Define trait
        impl FieldTrait for $pyname {
            // https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#specifying-placeholder-types-in-trait-definitions-with-associated-types
            fn init(
                &mut self,
                kwargs: Option<HashMap<String, types::InternalType>>,
            ) -> Result<(), pyo3::PyErr> {
                self.sz = 0;
                if let Some(options) = kwargs {
                    if let Some(remain) = options.get("remain") {
                        self.remain = remain.try_into()?;
                    }
                }
                Ok(())
            }
            fn any2i<'py>(
                &self,
                _: Option<&packet::Packet>,
                x: &Bound<'py, PyAny>,
            ) -> Result<types::InternalType, PyErr> {
                Ok(types::InternalType::Bytes(x.extract()?))
            }
            fn m2i(
                &self,
                _: &packet::Packet,
                x: types::MachineType,
            ) -> Result<types::InternalType, PyErr> {
                Ok(x.as_internal())
            }
            fn i2m(
                &self,
                _: &packet::Packet,
                x: Option<types::InternalType>,
            ) -> Result<types::MachineType, PyErr> {
                if let Some(val) = x {
                    Ok(val.as_machine())
                } else {
                    Ok(types::MachineType::Bytes(Vec::new()))
                }
            }
            fn addfield(
                &self,
                pkt: &packet::Packet,
                mut s: Vec<u8>,
                val: Option<types::InternalType>,
            ) -> Result<Vec<u8>, PyErr> {
                let mval = self.i2m(pkt, val)?;
                match mval {
                    types::MachineType::Bytes(x) => {
                        s.extend_from_slice(&x);
                        return Ok(s);
                    }
                    _ => Err(PyTypeError::new_err("Bad type !")),
                }
            }
            fn getfield<'a>(
                &self,
                pkt: &packet::Packet,
                x: &'a [u8],
            ) -> Result<(types::InternalType, &'a [u8]), PyErr> {
                Ok((self.m2i(pkt, types::MachineType::Bytes(x.to_vec()))?, &[]))
            }
        }

        // Define python aliases
        // https://pyo3.rs/v0.20.2/trait_bounds#implementation-of-the-trait-bounds-for-the-python-class
        #[pymethods]
        impl $pyname {
            #[pyo3(signature = (name, default, **kwargs))]
            #[staticmethod]
            pub fn new<'py>(
                name: String,
                default: &Bound<'py, PyAny>,
                kwargs: Option<HashMap<String, types::InternalType>>,
            ) -> PyResult<FieldProxy> {
                let mut x = $pyname { sz: 0, remain: 0 };
                x.init(kwargs)?;
                Ok(FieldProxy {
                    name: name,
                    default: types::InternalType::Bytes(default.extract()?),
                    sz: x.sz,
                    fieldtype: FieldType::$pyname(x),
                })
            }
            pub fn m2i(
                &self,
                pkt: &packet::Packet,
                x: types::MachineType,
            ) -> Result<types::InternalType, PyErr> {
                FieldTrait::m2i(self, pkt, x)
            }
            #[pyo3(signature=(pkt, x=None))]
            pub fn i2m(
                &self,
                pkt: &packet::Packet,
                x: Option<types::InternalType>,
            ) -> Result<types::MachineType, PyErr> {
                FieldTrait::i2m(self, pkt, x)
            }
            #[pyo3(signature=(pkt, s, val=None))]
            pub fn addfield(
                &self,
                pkt: &packet::Packet,
                s: Vec<u8>,
                val: Option<types::InternalType>,
            ) -> Result<Vec<u8>, PyErr> {
                FieldTrait::addfield(self, pkt, s, val)
            }
            pub fn getfield<'a>(
                &self,
                pkt: &packet::Packet,
                x: &'a [u8],
            ) -> Result<(types::InternalType, &'a [u8]), PyErr> {
                FieldTrait::getfield(self, pkt, x)
            }
        }
    };
}

_StrField![StrField];

// Generic

#[derive(Clone)]
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
    StrField(StrField),
}

// Huh, I feel very dumb writing this.

impl FieldType {
    pub fn as_trait(&self) -> Box<&dyn FieldTrait> {
        match self {
            FieldType::ByteField(x) => Box::new(x),
            FieldType::ShortField(x) => Box::new(x),
            FieldType::IntField(x) => Box::new(x),
            FieldType::LongField(x) => Box::new(x),
            FieldType::LEShortField(x) => Box::new(x),
            FieldType::LEIntField(x) => Box::new(x),
            FieldType::LELongField(x) => Box::new(x),
            FieldType::SignedByteField(x) => Box::new(x),
            FieldType::SignedShortField(x) => Box::new(x),
            FieldType::SignedIntField(x) => Box::new(x),
            FieldType::SignedLongField(x) => Box::new(x),
            FieldType::LESignedShortField(x) => Box::new(x),
            FieldType::LESignedIntField(x) => Box::new(x),
            FieldType::LESignedLongField(x) => Box::new(x),
            FieldType::StrField(x) => Box::new(x),
        }
    }
}

/*
 * FieldProxy is made to be passed to, or received from, the Python world.
 */

#[pyclass]
#[derive(Clone)]
pub struct FieldProxy {
    pub name: String,
    pub default: types::InternalType,
    pub sz: usize,
    pub fieldtype: FieldType,
}

/*
 * FieldList is a 'list of fields' type. Typically, fields_desc.
 */

pub type FieldList = Vec<FieldProxy>;

/*
 * Module definition into the Python world
 */

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
    m.add_class::<StrField>()?;
    Ok(())
}
