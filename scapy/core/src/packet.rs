use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use std::collections::HashMap;

use crate::fields::Field;
use crate::types;

/*
 * PacketClass is a structure created once per Packet class, and shared across
 * all Packet instances.
 */

type FieldList = Vec<Field>;

#[pyclass]
pub struct PacketClass {
    fields_desc: FieldList,
}

#[pymethods]
impl PacketClass {
    #[new]
    pub fn new(fields_desc: FieldList) -> Self {
        PacketClass { fields_desc: fields_desc }
    }

    #[pyo3(signature = (_pkt=None, **kwargs))]
    pub fn __call__(
        &self,
        _pkt: Option<&[u8]>,
        kwargs: Option<HashMap<String, types::InternalType>>,
    ) -> PyResult<Packet> {
        let mut p = Packet {
            fields_desc: self.fields_desc.clone(),
            fields: HashMap::new(),
            payload: None
        };
        if let Some(s) = _pkt {
            p.do_dissect(s)?;
        }
        Ok(p)
    }
}

/*
 * Packet is the rust equivalent of Scapy's main 'Packet' structure.
 * As definitions are done in Python, this is never really used directly.
 */
#[pyclass]
#[derive(Clone)]
pub struct Packet {
    fields_desc: FieldList,
    #[pyo3(get)]
    fields: HashMap<String, types::InternalType>,
    payload: Option<Box<Packet>>,
}

#[pymethods]
impl Packet {
    pub fn do_dissect(&mut self, mut s: &[u8]) -> PyResult<()> {
        for f in &self.fields_desc {
            let (fval, remaining) = f.fieldtype.as_trait().getfield(self, s)?;
            self.fields.insert(f.name.clone(), fval);
            s = remaining;
        }
        Ok(())
    }
    #[getter(payload)]
    fn get_payload(&self) -> Option<Packet> {
        if let Some(x) = &self.payload {
            Some((**x).clone())
        } else {
            None
        }
    }
    #[setter(payload)]
    fn set_payload(&mut self, payload: Option<Packet>) {
        if let Some(x) = payload {
            self.payload = Some(Box::new(x));
        } else {
            self.payload = None;
        }
    }
    pub fn __getattr__(&self, py: Python<'_>, attr: &str) -> PyResult<Py<PyAny>> {
        match self.fields.get(attr) {
            Some(value) => Ok(value.to_object(py)),
            None => Err(PyAttributeError::new_err("Attribute not found"))
        }
    }
}

#[pymodule]
pub fn packet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PacketClass>()?;
    m.add_class::<Packet>()?;
    Ok(())
}
