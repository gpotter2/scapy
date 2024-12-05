use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use crate::fields::{FieldList, StrField};
use crate::types::{self, InternalType};
use crate::utils::generate_uuid;

/*
 * All Packet classes are stored in this global hashmap.
 *
 * This allows to make the association in payload_guess work with multiple structures pointing
 * to the same ones, in addition to make it easy to pass a proxy to the Python world.
 */

static PACKET_CLASSES: LazyLock<Mutex<HashMap<String, Arc<Mutex<PacketClass>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/*
 * PacketClass is a structure created once per Packet class, and shared across
 * all Packet instances. It is a rust-only object, globally built and stored
 * in PACKET_CLASSES. All access to it's data are done through a PacketClassProxy.
 *
 * We need something like this to be able to handle bind_layers, for instance
 */

struct PacketClass {
    fields_desc: FieldList,
    _uuid: String,
    payload_guess: Vec<(Option<HashMap<String, types::InternalType>>, String)>,
    _overloaded_fields: HashMap<String, HashMap<String, types::InternalType>>,
}

/*
 * PacketClassProxy is a proxy class used from the Python and Rust worlds to access
 * the global PacketClass stored in PACKET_CLASSES. It's made to be copied, cloned, etc. around
 */

#[pyclass]
#[derive(Clone)]
pub struct PacketClassProxy {
    _uuid: String,
}

#[pymethods]
impl PacketClassProxy {
    #[new]
    pub fn new(fields_desc: FieldList) -> Self {
        // We create the PacketClass
        let pclass = PacketClass {
            fields_desc: fields_desc,
            _uuid: generate_uuid(),
            payload_guess: Vec::new(),
            _overloaded_fields: HashMap::new(),
        };
        // Create a proxy to it
        let pclassproxy = PacketClassProxy {
            _uuid: pclass._uuid.clone(),
        };
        // Then register it in PACKET_CLASSES
        PACKET_CLASSES
            .lock()
            .unwrap()
            .insert(pclass._uuid.clone(), Arc::new(Mutex::new(pclass)));
        // Finally return the proxy
        pclassproxy
    }

    #[pyo3(signature = (_pkt=None, **kwargs))]
    pub fn __call__(
        &self,
        _pkt: Option<&[u8]>,
        kwargs: Option<HashMap<String, types::InternalType>>,
    ) -> PyResult<Packet> {
        let mut p = Packet {
            proxy: PacketClassProxy {
                _uuid: self._uuid.clone(),
            },
            fields: HashMap::new(),
            payload: None,
        };
        if let Some(s) = _pkt {
            p.dissect(s)?;
        }
        Ok(p)
    }
}

impl PacketClassProxy {
    /*
     * Implements the important method: get_class.
     * This allows to un-alias the UUID to get a mutex towards the global PacketClass.
     */

    fn get_class(&self) -> Arc<Mutex<PacketClass>> {
        // PACKET_CLASSES must ALWAYS contain any created class.
        PACKET_CLASSES
            .lock()
            .unwrap()
            .get(&self._uuid)
            .unwrap()
            // We clone the Arc => increases reference count, doesn't actually clone the content.
            .clone()
    }
}

/*
 * The 'Raw' packet
 */

static RAW: LazyLock<PacketClassProxy> = LazyLock::new(|| {
    PacketClassProxy::new(
        [StrField::new("load".to_string(), InternalType::Bytes(Vec::new()), None).unwrap()]
            .to_vec(),
    )
});

/*
 * Packet is the rust equivalent of Scapy's main 'Packet' structure. It's the instance object
 * of a PacketClass.
 *
 * As definitions are done in Python, this is never really used directly.
 */

#[pyclass]
#[derive(Clone)]
pub struct Packet {
    proxy: PacketClassProxy,
    // Stores the current values of the various fields
    #[pyo3(get)]
    fields: HashMap<String, types::InternalType>,
    // Payload
    payload: Option<Box<Packet>>,
}

impl Packet {
    fn getfieldval(&self, attr: &String) -> PyResult<&types::InternalType> {
        if self.fields.contains_key(attr) {
            return Ok(self.fields.get(attr).unwrap());
        } else {
            if let Some(payload) = &self.payload {
                payload.getfieldval(attr)
            } else {
                Err(PyAttributeError::new_err("Attribute not found"))
            }
        }
    }
}

#[pymethods]
impl Packet {
    pub fn guess_payload_class(&self, _s: &[u8]) -> PyResult<PacketClassProxy> {
        let cls = self.proxy.get_class();
        let cls_locked = cls.lock().unwrap();
        let cls_uuid = cls_locked
            .payload_guess
            .iter()
            .filter(|(ofvals, _)| {
                if let Some(fvals) = ofvals {
                    return fvals.iter().all(|(k, v)| {
                        if let Ok(fval) = self.getfieldval(k) {
                            v == fval
                        } else {
                            false
                        }
                    });
                } else {
                    return true;
                }
            })
            .map(|(_, cls)| cls)
            .next();
        if let Some(cls_uuid) = cls_uuid {
            Ok(PacketClassProxy {
                _uuid: cls_uuid.clone(),
            })
        } else {
            Ok(RAW.clone())
        }
    }

    // Dissection
    pub fn do_dissect<'a>(&mut self, mut s: &'a [u8]) -> PyResult<&'a [u8]> {
        for f in &self.proxy.get_class().lock().unwrap().fields_desc {
            let (fval, remaining) = f.fieldtype.as_trait().getfield(self, s)?;
            self.fields.insert(f.name.clone(), fval);
            s = remaining;
        }
        Ok(s)
    }
    pub fn do_dissect_payload(&mut self, s: &[u8]) -> PyResult<()> {
        if s.is_empty() {
            Ok(())
        } else {
            let cls: PacketClassProxy = self.guess_payload_class(&s)?;
            let pkt = match cls.__call__(Some(s), None) {
                Ok(pkt) => pkt,
                Err(_) => RAW.__call__(Some(s), None).unwrap(),
            };
            self.add_payload(pkt);
            Ok(())
        }
    }
    pub fn dissect(&mut self, s: &[u8]) -> PyResult<()> {
        let s = self.do_dissect(s)?;
        self.do_dissect_payload(s)?;
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

/*
 * Standard binding methods
 */

#[pyfunction]
#[pyo3(signature = (lower, upper, **kwargs))]
pub fn bind_bottom_up(
    lower: &mut PacketClassProxy,
    upper: &PacketClassProxy,
    kwargs: Option<HashMap<String, types::InternalType>>,
) {
    lower
        .get_class()
        .lock()
        .unwrap()
        .payload_guess
        .push((kwargs, upper._uuid.clone()));
}

#[pyfunction]
#[pyo3(signature = (lower, upper, **kwargs))]
pub fn bind_top_down(
    lower: &PacketClassProxy,
    upper: &mut PacketClassProxy,
    kwargs: Option<HashMap<String, types::InternalType>>,
) {
    if let Some(fval) = kwargs {
        upper
            .get_class()
            .lock()
            .unwrap()
            ._overloaded_fields
            .insert(lower._uuid.clone(), fval);
    }
}

#[pyfunction]
#[pyo3(signature = (lower, upper, **kwargs))]
pub fn bind_layers(
    lower: &PacketClassProxy,
    upper: &mut PacketClassProxy,
    kwargs: Option<HashMap<String, types::InternalType>>,
) {
    bind_top_down(lower, upper, kwargs.clone());
    bind_top_down(lower, upper, kwargs);
}

/*
 * Module definition into the Python world
 */

#[pymodule]
pub fn packet(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PacketClassProxy>()?;
    m.add_class::<Packet>()?;
    m.add("Raw", Py::new(m.py(), (*RAW).clone())?)?;
    m.add_function(wrap_pyfunction!(bind_bottom_up, m)?)?;
    m.add_function(wrap_pyfunction!(bind_top_down, m)?)?;
    m.add_function(wrap_pyfunction!(bind_layers, m)?)?;
    Ok(())
}
