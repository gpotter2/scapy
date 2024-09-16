use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

use crate::fields;
use crate::types;

/*
 * PacketClass is a structure created once per Packet class, and shared across
 * all Packet instances.
 */

#[pyclass]
#[derive(FromPyObject)]
pub struct PacketClass {
    fields_desc: Vec<fields::FieldType>,
}

#[pymethods]
impl PacketClass {
    #[new]
    pub fn new(fields_desc: Vec<fields::FieldType>) -> Self {
        PacketClass {
            fields_desc: fields_desc,
        }
    }

    #[pyo3(signature = (_pkt=None, **kwargs))]
    pub fn __call__(
        &self,
        _pkt: Option<&[u8]>,
        kwargs: Option<HashMap<String, types::InternalType>>,
    ) -> Packet {
        Packet {
            fields: match kwargs {
                Some(x) => x,
                None => HashMap::new()
            },
            fields_desc: self.fields_desc.clone(),
        }
    }
}

/*
 * Packet is the rust equivalent of Scapy's main 'Packet' structure.
 * As definitions are done in Python, this is never really used directly.
 */
#[pyclass]
pub struct Packet {
    fields_desc: Vec<fields::FieldType>,
    #[pyo3(get)]
    fields: HashMap<String, types::InternalType>,
}

impl Packet {}

#[pymodule]
pub fn packet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PacketClass>()?;
    m.add_class::<Packet>()?;
    Ok(())
}
