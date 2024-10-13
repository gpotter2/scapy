use pyo3::prelude::*;

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
        }
    }
}

// Export

#[pymodule]
pub fn types(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<InternalType>()?;
    Ok(())
}