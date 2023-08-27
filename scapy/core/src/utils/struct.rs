use pyo3::exceptions::PyValueError;
use pyo3::types::PyBytes;

pub fn calcsize(format: &str) -> Result<usize, &str> {
    // struct.calcsize in rust
    let mut it = format.chars();
    if let Some('@') = it.next() {
        // Native
        it.try_fold(0_usize, |acc, x| match x {
            'c' | 'b' | 'B' | '?' => Ok(acc + 1),
            'h' | 'H' => Ok(acc + std::mem::size_of::<std::ffi::c_short>()),
            'i' | 'I' | 'f' => Ok(acc + std::mem::size_of::<std::ffi::c_int>()),
            'l' | 'L' => Ok(acc + std::mem::size_of::<std::ffi::c_long>()),
            'q' | 'Q' | 'd' => Ok(acc + std::mem::size_of::<std::ffi::c_longlong>()),
            _ => Err("bad char in struct format"),
        })
    } else {
        // Standard size
        // https://docs.python.org/3/library/struct.html#format-characters
        it.try_fold(0_usize, |acc, x| match x {
            'c' | 'b' | 'B' | '?' => Ok(acc + 1),
            'h' | 'H' => Ok(acc + 2),
            'i' | 'I' | 'l' | 'L' | 'f' => Ok(acc + 4),
            'q' | 'Q' | 'd' => Ok(acc + 8),
            _ => Err("bad char in struct format"),
        })
    }
}

enum StructOrder {
    NativeOrderNative,
    NativeOrderStandard,
    LittleEndianStandard,
    BigEndianStandard,
}
enum StructValue {
    Char(u8),
    SignedByte(i8),
    UnsignedByte(u8),
    Short(i16),
    UnsignedShort(u16),
    Int(i32),
    UnsignedInt(u32),
    Long(i64),
    UnsignedLong(u64),
    LongLong(i128),
    UnsignedLongLong(u128),
    Float(f32),
    Double(f64),
}

impl StructValue {
    pub fn to_bytes(&self, order: StructOrder) -> Box<[u8]> {
        match order {
            StructOrder::NativeOrderNative => match self {
                StructValue::Char(x) => {
                    Box::new(core::ffi::c_char::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::SignedByte(x) => {
                    Box::new(core::ffi::c_schar::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::UnsignedByte(x) => {
                    Box::new(core::ffi::c_uchar::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::Short(x) => {
                    Box::new(core::ffi::c_short::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::UnsignedShort(x) => {
                    Box::new(core::ffi::c_ushort::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::Int(x) => {
                    Box::new(core::ffi::c_int::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::UnsignedInt(x) => {
                    Box::new(core::ffi::c_uint::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::Long(x) => {
                    Box::new(core::ffi::c_long::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::UnsignedLong(x) => {
                    Box::new(core::ffi::c_ulong::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::LongLong(x) => {
                    Box::new(core::ffi::c_longlong::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::UnsignedLongLong(x) => {
                    Box::new(core::ffi::c_ulonglong::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::Float(x) => {
                    Box::new(core::ffi::c_float::try_from(x).unwrap().to_ne_bytes())
                }
                StructValue::Double(x) => {
                    Box::new(core::ffi::c_double::try_from(x).unwrap().to_ne_bytes())
                }
            },
            StructOrder::NativeOrderStandard => match self {
                StructValue::Char(x) => Box::new(x.to_ne_bytes()),
                StructValue::SignedByte(x) => Box::new(x.to_ne_bytes()),
                StructValue::UnsignedByte(x) => Box::new(x.to_ne_bytes()),
                StructValue::Short(x) => Box::new(x.to_ne_bytes()),
                StructValue::UnsignedShort(x) => Box::new(x.to_ne_bytes()),
                StructValue::Int(x) => Box::new(x.to_ne_bytes()),
                StructValue::UnsignedInt(x) => Box::new(x.to_ne_bytes()),
                StructValue::Long(x) => Box::new(x.to_ne_bytes()),
                StructValue::UnsignedLong(x) => Box::new(x.to_ne_bytes()),
                StructValue::LongLong(x) => Box::new(x.to_ne_bytes()),
                StructValue::UnsignedLongLong(x) => Box::new(x.to_ne_bytes()),
                StructValue::Float(x) => Box::new(x.to_ne_bytes()),
                StructValue::Double(x) => Box::new(x.to_ne_bytes()),
            },
            StructOrder::LittleEndianStandard => match self {
                StructValue::Char(x) => Box::new(x.to_le_bytes()),
                StructValue::SignedByte(x) => Box::new(x.to_le_bytes()),
                StructValue::UnsignedByte(x) => Box::new(x.to_le_bytes()),
                StructValue::Short(x) => Box::new(x.to_le_bytes()),
                StructValue::UnsignedShort(x) => Box::new(x.to_le_bytes()),
                StructValue::Int(x) => Box::new(x.to_le_bytes()),
                StructValue::UnsignedInt(x) => Box::new(x.to_le_bytes()),
                StructValue::Long(x) => Box::new(x.to_le_bytes()),
                StructValue::UnsignedLong(x) => Box::new(x.to_le_bytes()),
                StructValue::LongLong(x) => Box::new(x.to_le_bytes()),
                StructValue::UnsignedLongLong(x) => Box::new(x.to_le_bytes()),
                StructValue::Float(x) => Box::new(x.to_le_bytes()),
                StructValue::Double(x) => Box::new(x.to_le_bytes()),
            },
            StructOrder::BigEndianStandard => match self {
                StructValue::Char(x) => Box::new(x.to_be_bytes()),
                StructValue::SignedByte(x) => Box::new(x.to_be_bytes()),
                StructValue::UnsignedByte(x) => Box::new(x.to_be_bytes()),
                StructValue::Short(x) => Box::new(x.to_be_bytes()),
                StructValue::UnsignedShort(x) => Box::new(x.to_be_bytes()),
                StructValue::Int(x) => Box::new(x.to_be_bytes()),
                StructValue::UnsignedInt(x) => Box::new(x.to_be_bytes()),
                StructValue::Long(x) => Box::new(x.to_be_bytes()),
                StructValue::UnsignedLong(x) => Box::new(x.to_be_bytes()),
                StructValue::LongLong(x) => Box::new(x.to_be_bytes()),
                StructValue::UnsignedLongLong(x) => Box::new(x.to_be_bytes()),
                StructValue::Float(x) => Box::new(x.to_be_bytes()),
                StructValue::Double(x) => Box::new(x.to_be_bytes()),
            },
        }
    }
}

pub fn pack(format: &str, val: &[StructValue]) -> Result<Box<[u8]>, &str> {
    // struct.pack in rust with 1 argument
    let mut it = format.chars();
    let order: StructOrder = match it.next() {
        Some('@') => StructOrder::NativeOrderNative,
        Some('=') => StructOrder::NativeOrderStandard,
        Some('<') => StructOrder::LittleEndianStandard,
        Some('>') | Some('!') => StructOrder::BigEndianStandard,
        _ => return Err("bad char in struct format"),
    };
    Ok(match it.fold([], |acc, x| match x {
        Some('c') => StructValue::Char(val.extract::<u8>(py)?),
        Some('b') => StructValue::SignedByte(val.extract::<i8>(py)?),
        Some('B') => StructValue::UnsignedByte(val.extract::<u8>(py)?),
        Some('h') => StructValue::Short(val.extract::<i16>(py)?),
        Some('H') => StructValue::UnsignedShort(val.extract::<u16>(py)?),
        Some('i') => StructValue::Int(val.extract::<i32>(py)?),
        Some('I') => StructValue::UnsignedInt(val.extract::<u32>(py)?),
        Some('l') => StructValue::Long(val.extract::<i64>(py)?),
        Some('L') => StructValue::UnsignedLong(val.extract::<u64>(py)?),
        Some('q') => StructValue::LongLong(val.extract::<i128>(py)?),
        Some('Q') => StructValue::UnsignedLongLong(val.extract::<u128>(py)?),
        Some('f') => StructValue::Float(val.extract::<f32>(py)?),
        Some('d') => StructValue::Double(val.extract::<f64>(py)?),
        _ => return Err("bad char in struct format"),
    }))
}

// pub fn unpack(format: &str, val: &[u8]) -> PyResult<Struct> {
//     // struct.unpack in rust with 1 argument
//     let mut it = format.chars();
//     Ok(Struct {
//         order: match it.next() {
//             Some('@') => StructOrder::NativeOrderNative,
//             Some('=') => StructOrder::NativeOrderStandard,
//             Some('<') => StructOrder::LittleEndianStandard,
//             Some('>') | Some('!') => StructOrder::BigEndianStandard,
//             _ => return Err(PyValueError::new_err("bad char in struct format")),
//         },
//         value: Python::with_gil(|py| match it.next() {
//             Some('c') => Ok(StructValue::Char(val.extract::<u8>(py)?)),
//             Some('b') => Ok(StructValue::SignedByte(val.extract::<i8>(py)?)),
//             Some('B') => Ok(StructValue::UnsignedByte(val.extract::<u8>(py)?)),
//             Some('h') => Ok(StructValue::Short(val.extract::<i16>(py)?)),
//             Some('H') => Ok(StructValue::UnsignedShort(val.extract::<u16>(py)?)),
//             Some('i') => Ok(StructValue::Int(val.extract::<i32>(py)?)),
//             Some('I') => Ok(StructValue::UnsignedInt(val.extract::<u32>(py)?)),
//             Some('l') => Ok(StructValue::Long(val.extract::<i64>(py)?)),
//             Some('L') => Ok(StructValue::UnsignedLong(val.extract::<u64>(py)?)),
//             Some('q') => Ok(StructValue::LongLong(val.extract::<i128>(py)?)),
//             Some('Q') => Ok(StructValue::UnsignedLongLong(val.extract::<u128>(py)?)),
//             Some('f') => Ok(StructValue::Float(val.extract::<f32>(py)?)),
//             Some('d') => Ok(StructValue::Double(val.extract::<f64>(py)?)),
//             _ => return Err(PyValueError::new_err("bad char in struct format")),
//         })?,
//     })
// }