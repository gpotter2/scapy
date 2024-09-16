/*
 * Machine type.
 * This implements the conversion between bytes and the internal values.
 */
use pyo3::prelude::*;

pub trait MachineType {
    type U8Array;
    fn from_le_bytes(bytes: Self::U8Array) -> Self;
    fn from_be_bytes(bytes: Self::U8Array) -> Self;
    fn to_le_bytes(x: Self) -> Self::U8Array;
    fn to_be_bytes(x: Self) -> Self::U8Array;
}

macro_rules! impl_Ints (( $($int:ident),* ) => {
    $(
        impl MachineType for $int {
            type U8Array = [u8; std::mem::size_of::<Self>()];
            fn from_le_bytes(bytes: Self::U8Array) -> Self {
                Self::from_le_bytes(bytes)
            }
            fn from_be_bytes(bytes: Self::U8Array) -> Self {
                Self::from_be_bytes(bytes)
            }
            fn to_le_bytes(x: Self) -> Self::U8Array {
                x.to_le_bytes()
            }
            fn to_be_bytes(x: Self) -> Self::U8Array {
                x.to_be_bytes()
            }
        }
    )*
});

impl_Ints!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128);

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
}
