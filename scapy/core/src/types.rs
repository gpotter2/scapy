use pyo3::exceptions::PyValueError;
use pyo3::{prelude::*, IntoPyObjectExt};
use std::convert::TryInto;

/*
 * Internal type.
 * This implements how the values are stored within Scapy.
 */

// NOTE: This file looks extremly dumb, but I, for the love of god, could not figure out
// how to make it look nicer. It sounds extremly dumb, but it seems rust just WAAANNNTTTSS you
// to unpack that f****** enum.

#[pyclass]
#[derive(Clone, Debug)]
#[derive(IntoPyObjectRef)]
pub enum InternalType {
    Byte(u8),
    SignedByte(i8),
    Short(u16),
    SignedShort(i16),
    Int(u32),
    SignedInt(i32),
    Long(u64),
    SignedLong(i64),
    LongLong(u128),
    SignedLongLong(i128),
    String(String),
    Bytes(Vec<u8>),
}

impl PartialEq for InternalType {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (InternalType::Byte(a), InternalType::Byte(b)) => a == b,
            (InternalType::SignedByte(a), InternalType::SignedByte(b)) => a == b,
            (InternalType::Short(a), InternalType::Short(b)) => a == b,
            (InternalType::SignedShort(a), InternalType::SignedShort(b)) => a == b,
            (InternalType::Int(a), InternalType::Int(b)) => a == b,
            (InternalType::SignedInt(a), InternalType::SignedInt(b)) => a == b,
            (InternalType::Long(a), InternalType::Long(b)) => a == b,
            (InternalType::SignedLong(a), InternalType::SignedLong(b)) => a == b,
            (InternalType::LongLong(a), InternalType::LongLong(b)) => a == b,
            (InternalType::SignedLongLong(a), InternalType::SignedLongLong(b)) => a == b,
            (InternalType::String(a), InternalType::String(b)) => a == b,
            (InternalType::Bytes(a), InternalType::Bytes(b)) => a == b,
            _ => false,
        }
    }
}

impl std::fmt::Display for InternalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalType::Byte(x) => write!(f, "Byte({})", x),
            InternalType::SignedByte(x) => write!(f, "SignedByte({})", x),
            InternalType::Short(x) => write!(f, "Short({})", x),
            InternalType::SignedShort(x) => write!(f, "SignedShort({})", x),
            InternalType::Int(x) => write!(f, "Int({})", x),
            InternalType::SignedInt(x) => write!(f, "SignedInt({})", x),
            InternalType::Long(x) => write!(f, "Long({})", x),
            InternalType::SignedLong(x) => write!(f, "SignedLong({})", x),
            InternalType::LongLong(x) => write!(f, "LongLong({})", x),
            InternalType::SignedLongLong(x) => write!(f, "SignedLongLong({})", x),
            InternalType::String(x) => write!(f, "String({})", x),
            InternalType::Bytes(x) => write!(f, "Bytes({:?})", x),
        }
    }
}

#[pyclass]
#[derive(Clone)]
pub enum MachineType {
    Byte(u8),
    SignedByte(i8),
    Short(u16),
    SignedShort(i16),
    Int(u32),
    SignedInt(i32),
    Long(u64),
    SignedLong(i64),
    LongLong(u128),
    SignedLongLong(i128),
    Bytes(Vec<u8>),
}

impl MachineType {
    pub fn as_internal(&self) -> InternalType {
        match self {
            MachineType::Byte(x) => InternalType::Byte(*x),
            MachineType::SignedByte(x) => InternalType::SignedByte(*x),
            MachineType::Short(x) => InternalType::Short(*x),
            MachineType::SignedShort(x) => InternalType::SignedShort(*x),
            MachineType::Int(x) => InternalType::Int(*x),
            MachineType::SignedInt(x) => InternalType::SignedInt(*x),
            MachineType::Long(x) => InternalType::Long(*x),
            MachineType::SignedLong(x) => InternalType::SignedLong(*x),
            MachineType::LongLong(x) => InternalType::LongLong(*x),
            MachineType::SignedLongLong(x) => InternalType::SignedLongLong(*x),
            MachineType::Bytes(x) => InternalType::Bytes(x.clone()),
        }
    }
}

impl InternalType {
    pub fn as_machine(&self) -> MachineType {
        match self {
            InternalType::Byte(x) => MachineType::Byte(*x),
            InternalType::SignedByte(x) => MachineType::SignedByte(*x),
            InternalType::Short(x) => MachineType::Short(*x),
            InternalType::SignedShort(x) => MachineType::SignedShort(*x),
            InternalType::Int(x) => MachineType::Int(*x),
            InternalType::SignedInt(x) => MachineType::SignedInt(*x),
            InternalType::Long(x) => MachineType::Long(*x),
            InternalType::SignedLong(x) => MachineType::SignedLong(*x),
            InternalType::LongLong(x) => MachineType::LongLong(*x),
            InternalType::SignedLongLong(x) => MachineType::SignedLongLong(*x),
            InternalType::String(x) => MachineType::Bytes(x.as_bytes().to_vec()),
            InternalType::Bytes(x) => MachineType::Bytes(x.clone()),
        }
    }
    pub fn to_object(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match self {
            InternalType::Byte(x) => x.into_py_any(py),
            InternalType::SignedByte(x) => x.into_py_any(py),
            InternalType::Short(x) => x.into_py_any(py),
            InternalType::SignedShort(x) => x.into_py_any(py),
            InternalType::Int(x) => x.into_py_any(py),
            InternalType::SignedInt(x) => x.into_py_any(py),
            InternalType::Long(x) => x.into_py_any(py),
            InternalType::SignedLong(x) => x.into_py_any(py),
            InternalType::LongLong(x) => x.into_py_any(py),
            InternalType::SignedLongLong(x) => x.into_py_any(py),
            InternalType::String(x) => x.into_py_any(py),
            InternalType::Bytes(x) => x.into_py_any(py),
        }
    }
}



// Try to be a bit smart: this implements all casting of InternalTypes using a macro...

macro_rules! impl_TryIntos (( $($typ:ident),* ) => {
    $(
        impl TryInto<$typ> for &InternalType {
            type Error = PyErr;

            fn try_into(self) -> Result<$typ, Self::Error> {
                match self {
                    InternalType::Byte(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    InternalType::SignedByte(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    InternalType::Short(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    InternalType::SignedShort(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    InternalType::Int(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    InternalType::SignedInt(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    InternalType::Long(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    InternalType::SignedLong(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    InternalType::LongLong(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    InternalType::SignedLongLong(x) => (*x).try_into().map_err(|_| {PyValueError::new_err("Bad Type")}),
                    _ => Err(PyValueError::new_err("Bad Type"))
                }
            }
        }
    )*
});

impl_TryIntos!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize);

/*
 * Module definition into the Python world
 */

#[pymodule]
pub fn types(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<InternalType>()?;
    Ok(())
}
