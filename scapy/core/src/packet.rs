use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::fields::{Field, StrField};
use crate::types::{self, InternalType};

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
        PacketClass {
            fields_desc: fields_desc,
        }
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
            payload_guess: Vec::new(),
            overloaded_fields: HashMap::new(),
            payload: None,
        };
        if let Some(s) = _pkt {
            p.do_dissect(s)?;
        }
        Ok(p)
    }
}

static RAW: LazyLock<PacketClass> = LazyLock::new(|| PacketClass {
    fields_desc: [
        StrField::new("load".to_string(), InternalType::Bytes(Vec::new()), None).unwrap(),
    ]
    .to_vec(),
});

/*
 * Packet is the rust equivalent of Scapy's main 'Packet' structure.
 * As definitions are done in Python, this is never really used directly.
 */
#[pyclass]
#[derive(Clone)]
pub struct Packet {
    // The various fields that make up a Packet
    fields_desc: FieldList,
    // Stores the current values of the various fields
    #[pyo3(get)]
    fields: HashMap<String, types::InternalType>,
    // Store fields for dissection
    #[pyo3(get)]
    payload_guess: Vec<(HashMap<String, types::InternalType>, String)>,
    // Store fields for build
    overloaded_fields: HashMap<String, types::InternalType>,
    // Payload
    payload: Option<Box<Packet>>,
}

impl Packet {
    pub fn guess_payload_class(&self, s: &[u8]) -> &PacketClass {
        &RAW
    }
}

#[pymethods]
impl Packet {
    // Dissection
    pub fn do_dissect(&mut self, mut s: &[u8]) -> PyResult<()> {
        for f in &self.fields_desc {
            let (fval, remaining) = f.fieldtype.as_trait().getfield(self, s)?;
            self.fields.insert(f.name.clone(), fval);
            s = remaining;
        }
        Ok(())
    }
    pub fn do_dissect_payload(&mut self, s: &[u8]) -> PyResult<()> {
        if s.is_empty() {
            Ok(())
        } else {
            let cls: &PacketClass = self.guess_payload_class(&s);
            let pkt = match cls.__call__(Some(s), None) {
                Ok(pkt) => pkt,
                Err(_) => RAW.__call__(Some(s), None).unwrap(),
            };
            self.add_payload(pkt);
            Ok(())
        }
    }
    pub fn dissect(&mut self, mut s: &[u8]) -> PyResult<()> {
        Ok(())
    }

    // .payload attribute
    #[pyo3(signature = (payload))]
    fn add_payload(&mut self, payload: Packet) {
        if let Some(pay) = &mut self.payload {
            pay.add_payload(payload);
        } else {
            self.payload = Some(Box::new(payload));
        }
    }
    fn remove_payload(&mut self) {
        self.payload = None;
        self.overloaded_fields.clear();
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
            self.remove_payload();
            self.add_payload(x);
        } else {
            self.payload = None;
        }
    }

    // return a field's value
    pub fn __getattr__(&self, py: Python<'_>, attr: &str) -> PyResult<Py<PyAny>> {
        match self.fields.get(attr) {
            Some(value) => Ok(value.to_object(py)),
            None => Err(PyAttributeError::new_err("Attribute not found")),
        }
    }
}

#[pymodule]
pub fn packet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PacketClass>()?;
    m.add_class::<Packet>()?;
    Ok(())
}
