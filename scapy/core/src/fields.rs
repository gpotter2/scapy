/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * This file is part of Scapy
 * See https://scapy.net/ for more information
 * Copyright (C) Gabriel Potter
 */

use std::borrow::Cow;
use std::collections::HashMap;

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;

use crate::packet;
use crate::types;

/*
 * FieldTrait is the common trait that defines the behavior of Fields.
 * For more information on how this works, please refer to the
 * 'Adding new protocols' chapter in the online documentation:
 * https://scapy.readthedocs.io/en/stable/build_dissect.html
 */

pub trait FieldTrait {
    // &[u8] is used when dissecting
    // Vec<u8> is used when building
    fn init(&mut self, kwargs: Option<HashMap<String, types::InternalType>>) -> PyResult<()>;
    fn any2i<'py>(
        &self,
        pkt: Option<&packet::Packet>,
        x: &Option<&Bound<'py, PyAny>>,
    ) -> Result<types::InternalType, PyErr>;
    fn m2i(
        &self,
        pkt: &packet::Packet,
        x: types::MachineType,
    ) -> Result<types::InternalType, PyErr>;
    fn i2m(
        &self,
        pkt: &packet::Packet,
        x: &Option<&types::InternalType>,
    ) -> Result<types::MachineType, PyErr>;
    fn addfield(
        &self,
        pkt: &packet::Packet,
        s: Vec<u8>,
        val: &Option<&types::InternalType>,
    ) -> Result<Vec<u8>, PyErr>;
    fn getfield<'a>(
        &self,
        pkt: &packet::Packet,
        x: Cow<'a, [u8]>,
    ) -> Result<(Cow<'a, [u8]>, types::InternalType), PyErr>;
}

/*
 * Standard fields are implemented thanks to a macro that allows to
 * duplicate their definitions depending on a type parameters.
 */

macro_rules! Field {
    /*
     * $pyname is the Python name of this field, e.g. 'ByteField'
     * $i is the types::InternalType::$i used for this field. e.g. 'Byte'
     * $m is the rust type that is used for binary equivalent. e.g. u8
     * $leendian indicates whether the endianness is LowEndian or not. e.g. false
     */
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
                x: &Option<&Bound<'py, PyAny>>,
            ) -> Result<types::InternalType, PyErr> {
                if let Some(x) = x {
                    Ok(types::InternalType::$i(x.extract()?))
                } else {
                    Ok(types::InternalType::$i(0))
                }
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
                x: &Option<&types::InternalType>,
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
                val: &Option<&types::InternalType>,
            ) -> Result<Vec<u8>, PyErr> {
                let mval = FieldTrait::i2m(self, pkt, val)?;
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
                x: Cow<'a, [u8]>,
            ) -> Result<(Cow<'a, [u8]>, types::InternalType), PyErr> {
                let val = self.m2i(
                    pkt,
                    if $leendian {
                        types::MachineType::$i(<$m>::from_le_bytes(x[..self.sz].try_into()?))
                    } else {
                        types::MachineType::$i(<$m>::from_be_bytes(x[..self.sz].try_into()?))
                    },
                )?;
                Ok((
                    match x {
                        Cow::Borrowed(x) => Cow::Borrowed(&x[self.sz..]),
                        Cow::Owned(x) => Cow::Owned(x[self.sz..].to_vec()),
                    },
                    val,
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
                default: Option<&Bound<'py, PyAny>>,
                kwargs: Option<HashMap<String, types::InternalType>>,
            ) -> PyResult<FieldProxy> {
                let mut x = $pyname { sz: 0 };
                x.init(kwargs)?;
                Ok(FieldProxy {
                    name: name,
                    default: if let Some(default) = default {
                        Some(types::InternalType::$i(default.extract()?))
                    } else {
                        None
                    },
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
                x: Option<&types::InternalType>,
            ) -> Result<types::MachineType, PyErr> {
                FieldTrait::i2m(self, pkt, &x)
            }
            #[pyo3(signature=(pkt, s, val=None))]
            pub fn addfield(
                &self,
                pkt: &packet::Packet,
                s: Vec<u8>,
                val: Option<&types::InternalType>,
            ) -> Result<Vec<u8>, PyErr> {
                FieldTrait::addfield(self, pkt, s, &val)
            }
            #[pyo3(signature=(pkt, x))]
            pub fn getfield<'a>(
                &self,
                pkt: &packet::Packet,
                x: &'a [u8],
            ) -> Result<(Vec<u8>, types::InternalType), PyErr> {
                FieldTrait::getfield(self, pkt, Cow::Borrowed(x))
                    .map(|(cow, internal)| (cow.into_owned(), internal))
            }
            #[getter]
            pub fn name(&self) -> &str {
                return stringify!($pyname);
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

/*
 * Same for string fields.
 */

macro_rules! _StrField {
    ($pyname:ident) => {
        #[pyclass]
        #[derive(Clone)]
        pub struct $pyname {
            sz: usize,
            remain: Option<usize>,
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
                        self.remain = Some(remain.try_into()?);
                    }
                }
                Ok(())
            }
            fn any2i<'py>(
                &self,
                _: Option<&packet::Packet>,
                x: &Option<&Bound<'py, PyAny>>,
            ) -> Result<types::InternalType, PyErr> {
                if let Some(x) = x {
                    Ok(types::InternalType::Bytes(x.extract()?))
                } else {
                    Ok(types::InternalType::Bytes(Vec::new()))
                }
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
                x: &Option<&types::InternalType>,
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
                val: &Option<&types::InternalType>,
            ) -> Result<Vec<u8>, PyErr> {
                let mval = FieldTrait::i2m(self, pkt, val)?;
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
                x: Cow<'a, [u8]>,
            ) -> Result<(Cow<'a, [u8]>, types::InternalType), PyErr> {
                Ok((
                    Cow::Borrowed(&[]),
                    self.m2i(pkt, types::MachineType::Bytes(x.to_vec()))?,
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
                default: Option<&Bound<'py, PyAny>>,
                kwargs: Option<HashMap<String, types::InternalType>>,
            ) -> PyResult<FieldProxy> {
                let mut x = $pyname {
                    sz: 0,
                    remain: None,
                };
                x.init(kwargs)?;
                Ok(FieldProxy {
                    name: name,
                    default: if let Some(default) = default {
                        Some(types::InternalType::Bytes(default.extract()?))
                    } else {
                        None
                    },
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
                x: Option<&types::InternalType>,
            ) -> Result<types::MachineType, PyErr> {
                FieldTrait::i2m(self, pkt, &x)
            }
            #[pyo3(signature=(pkt, s, val=None))]
            pub fn addfield(
                &self,
                pkt: &packet::Packet,
                s: Vec<u8>,
                val: Option<&types::InternalType>,
            ) -> Result<Vec<u8>, PyErr> {
                FieldTrait::addfield(self, pkt, s, &val)
            }
            pub fn getfield<'a>(
                &self,
                pkt: &packet::Packet,
                x: &'a [u8],
            ) -> Result<(Vec<u8>, types::InternalType), PyErr> {
                FieldTrait::getfield(self, pkt, Cow::Borrowed(x))
                    .map(|(cow, internal)| (cow.into_owned(), internal))
            }
        }
    };
}

_StrField![StrField];

/*
 * PythonField: a rust field that proxies all the methods to their Python counterparts.
 * This is used to implement Fields in Python.
 */

#[pyclass]
pub struct PythonField {
    #[pyo3(get)]
    pyfld: Py<PyAny>,
}

impl Clone for PythonField {
    fn clone(&self) -> Self {
        Python::with_gil(|py| Self {
            pyfld: self.pyfld.clone_ref(py),
        })
    }
}

impl FieldTrait for PythonField {
    fn init(&mut self, _kwargs: Option<HashMap<String, types::InternalType>>) -> PyResult<()> {
        Ok(())
    }

    fn any2i<'py>(
        &self,
        _pkt: Option<&packet::Packet>,
        _x: &Option<&Bound<'py, PyAny>>,
    ) -> Result<types::InternalType, PyErr> {
        let pkt = match _pkt {
            Some(_pkt) => Some(_pkt.clone()),
            None => None,
        };
        Python::with_gil(|py| {
            let v = self.pyfld.call_method1(py, "any2i", (pkt, _x))?;
            v.extract(py)
        })
    }

    fn m2i(
        &self,
        _pkt: &packet::Packet,
        _x: types::MachineType,
    ) -> Result<types::InternalType, PyErr> {
        Python::with_gil(|py| {
            let v = self.pyfld.call_method1(py, "m2i", (_pkt.clone(), _x))?;
            v.extract(py)
        })
    }

    fn i2m(
        &self,
        _pkt: &packet::Packet,
        _x: &Option<&types::InternalType>,
    ) -> Result<types::MachineType, PyErr> {
        Python::with_gil(|py| {
            let v = self.pyfld.call_method1(py, "i2m", (_pkt.clone(), _x))?;
            v.extract(py)
        })
    }

    fn addfield(
        &self,
        _pkt: &packet::Packet,
        _s: Vec<u8>,
        _val: &Option<&types::InternalType>,
    ) -> Result<Vec<u8>, PyErr> {
        Python::with_gil(|py| {
            let v = self
                .pyfld
                .call_method1(py, "addfield", (_pkt.clone(), _s, _val))?;
            v.extract(py)
        })
    }

    fn getfield<'py, 'a>(
        &self,
        _pkt: &packet::Packet,
        _x: Cow<'a, [u8]>,
    ) -> Result<(Cow<'a, [u8]>, types::InternalType), PyErr> {
        Python::with_gil(|py| {
            let v = self
                .pyfld
                .call_method1(py, "getfield", (_pkt.clone(), _x))?;
            v.extract::<(Vec<u8>, Py<PyAny>)>(py)
                .map(|(vec, internal)| {
                    (
                        Cow::Owned(vec),
                        types::InternalType::PythonFieldValue(types::ClonablePyAny(internal)),
                    )
                })
        })
    }
}

#[pymethods]
impl PythonField {
    #[pyo3(signature = (pyfld))]
    #[staticmethod]
    pub fn new<'py>(py: Python<'py>, pyfld: Py<PyAny>) -> PyResult<FieldProxy> {
        Ok(FieldProxy {
            name: pyfld.getattr(py, "name")?.extract(py)?,
            default: None,
            sz: pyfld.getattr(py, "sz")?.extract(py)?,
            fieldtype: FieldType::PythonField(PythonField { pyfld: pyfld }),
        })
    }
}

// Generic

/*
 * FieldType is an enum that includes all possible Field types. This is used
 * to differentiate the types from each other when stored as fields_desc.
 */

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
    PythonField(PythonField),
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
            FieldType::PythonField(x) => Box::new(x),
        }
    }
}

/*
 * FieldProxy is made to be passed to, or received from, the Python world.
 * It is an instance of a 'Field'.
 */

#[pyclass]
#[derive(Clone)]
pub struct FieldProxy {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub default: Option<types::InternalType>,
    #[pyo3(get)]
    pub sz: usize,
    pub fieldtype: FieldType,
}

#[pymethods]
impl FieldProxy {
    #[pyo3(signature = (_pkt, x))]
    pub fn i2h(
        &self,
        _pkt: &packet::Packet,
        x: Option<&types::InternalType>,
    ) -> PyResult<Py<PyAny>> {
        Python::with_gil(|py| match x {
            Some(x) => x.to_object(py),
            None => Ok(py.None()),
        })
    }
    #[pyo3(signature = (pkt, x))]
    pub fn h2i<'py>(
        &self,
        pkt: Option<&packet::Packet>,
        x: Option<&Bound<'py, PyAny>>,
    ) -> Result<types::InternalType, PyErr> {
        self.fieldtype.as_trait().any2i(pkt, &x)
    }
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
    m.add_class::<PythonField>()?;
    m.add_class::<StrField>()?;
    Ok(())
}
