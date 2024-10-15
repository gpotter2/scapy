use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::convert::TryInto;

/*
 * Internal type.
 * This implements how the values are stored within Scapy.
 */

#[pyclass]
#[derive(Clone)]
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
    pub fn to_object(&self, py: Python<'_>) -> Py<PyAny> {
        match self {
            InternalType::Byte(x) => x.to_object(py),
            InternalType::SignedByte(x) => x.to_object(py),
            InternalType::Short(x) => x.to_object(py),
            InternalType::SignedShort(x) => x.to_object(py),
            InternalType::Int(x) => x.to_object(py),
            InternalType::SignedInt(x) => x.to_object(py),
            InternalType::Long(x) => x.to_object(py),
            InternalType::SignedLong(x) => x.to_object(py),
            InternalType::LongLong(x) => x.to_object(py),
            InternalType::SignedLongLong(x) => x.to_object(py),
            InternalType::String(x) => x.to_object(py),
            InternalType::Bytes(x) => x.to_object(py),
        }
    }
}

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

// Type for **kwargs

// Export

#[pymodule]
pub fn types(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<InternalType>()?;
    Ok(())
}
