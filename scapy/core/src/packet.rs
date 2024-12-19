use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use pyo3::types::PyList;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use crate::fields::{FieldList, FieldProxy, StrField};
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
    name: String,
    fields_desc: FieldList,
    _uuid: String,
    payload_guess: Vec<(Option<HashMap<String, types::InternalType>>, String)>,
    _overload_fields: HashMap<String, HashMap<String, types::InternalType>>,
}

impl PacketClass {
    pub fn get_field(&self, attr: &String) -> PyResult<FieldProxy> {
        match self.fields_desc.iter().find(|f| &f.name == attr) {
            Some(x) => Ok(x.clone()),
            _ => Err(PyAttributeError::new_err("Unknown field name (get_field)")),
        }
    }
}

/*
 * PacketClassProxy is a proxy class used from the Python and Rust worlds to represent
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
    pub fn new(name: &str, fields_desc: FieldList) -> Self {
        // We create the PacketClass
        let pclass = PacketClass {
            name: name.to_string(),
            fields_desc: fields_desc,
            _uuid: generate_uuid(),
            payload_guess: Vec::new(),
            _overload_fields: HashMap::new(),
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

    /*
     * A PacketClassProxy is used by the Python world to instantiate a Packet object.
     * This is done through __call__, so that it acts like a Python type would.
     */

    #[pyo3(signature = (_pkt=None, **kwargs))]
    pub fn __call__(
        &self,
        _pkt: Option<&[u8]>,
        kwargs: Option<HashMap<String, pyo3::Bound<'_, pyo3::PyAny>>>,
    ) -> PyResult<Packet> {
        let proxy = PacketClassProxy {
            _uuid: self._uuid.clone(),
        };
        let mut p = Packet {
            default_fields: {
                let mut map = HashMap::new();
                for f in &proxy.get_class().lock().unwrap().fields_desc {
                    map.insert(f.name.clone(), f.default.clone());
                }
                map
            },
            proxy: proxy,
            fields: HashMap::new(),
            overloaded_fields: HashMap::new(),
            payload: None,
        };
        if let Some(s) = _pkt {
            // Doing dissection
            p.dissect(s)?;
        } else {
            // Adding default values for build
            if let Some(kwargs) = kwargs {
                for (attr, val) in kwargs {
                    p.setfieldval(attr, Some(&val))?;
                }
            }
        }
        Ok(p)
    }

    /*
     * For Python's repr()
     */

    pub fn __repr__(&self) -> String {
        format!(
            "<scapy.core.PacketClassProxy {}>",
            self.get_class().lock().unwrap().name
        )
    }

    /*
     * Getter for '.payload_guess'. DEBUG ONLY
     */
    #[getter(_payload_guess)]
    fn _payload_guess(&self) -> Vec<(Option<HashMap<String, InternalType>>, String)> {
        self.get_class().lock().unwrap().payload_guess.clone()
    }

    /*
     * Getter for '._overload_fields'.  DEBUG ONLY
     */
    #[getter(_overload_fields)]
    fn _overload_fields(&self) -> HashMap<String, HashMap<String, InternalType>> {
        self.get_class().lock().unwrap()._overload_fields.clone()
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
    Python::with_gil(|py| {
        PacketClassProxy::new(
            "Raw",
            [StrField::new("load".to_string(), Some(&PyList::empty(py)), None).unwrap()].to_vec(),
        )
    })
});

/*
 * Packet is the rust equivalent of Scapy's main 'Packet' structure. It's the instance object
 * of a PacketClass.
 *
 * As definitions are done in Python, this shouldn't really be used directly.
 */

#[pyclass]
#[derive(Clone)]
pub struct Packet {
    proxy: PacketClassProxy,
    // Stores the current values of the various fields
    #[pyo3(get)]
    fields: HashMap<String, Option<types::InternalType>>,
    #[pyo3(get)]
    default_fields: HashMap<String, Option<types::InternalType>>,
    #[pyo3(get)]
    overloaded_fields: HashMap<String, types::InternalType>,
    // Payload
    payload: Option<Box<Packet>>,
}

impl Packet {
    /*
     * Return a proxy to the field object based on it's name.
     */
    fn _get_field(&self, attr: &String) -> PyResult<FieldProxy> {
        self.proxy.get_class().lock().unwrap().get_field(attr)
    }

    /*
     * Get / Set an internal field's value.
     */

    fn _getfieldval(&self, attr: &String) -> PyResult<Option<&types::InternalType>> {
        if self.fields.contains_key(attr) {
            return Ok(self.fields.get(attr).unwrap().as_ref());
        } else if self.overloaded_fields.contains_key(attr) {
            return Ok(Some(self.overloaded_fields.get(attr).unwrap()));
        } else if self.default_fields.contains_key(attr) {
            return Ok(self.default_fields.get(attr).unwrap().as_ref());
        } else {
            if let Some(payload) = &self.payload {
                payload._getfieldval(attr)
            } else {
                Err(PyAttributeError::new_err("Attribute not found"))
            }
        }
    }
}

#[pymethods]
impl Packet {
    /*
     * This method guesses the class of the payload based on its current fields.
     */
    pub fn guess_payload_class(&self, _s: &[u8]) -> PyResult<PacketClassProxy> {
        let cls = self.proxy.get_class();
        let cls_locked = cls.lock().unwrap();
        let cls_uuid = cls_locked
            .payload_guess
            .iter()
            .filter(|(ofvals, _)| {
                if let Some(fvals) = ofvals {
                    return fvals.iter().all(|(k, v)| {
                        if let Ok(Some(fval)) = self._getfieldval(k) {
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

    /*
     * Internal function called to perform the dissection of the current Packet's fields
     */

    fn do_dissect<'a>(&mut self, mut s: &'a [u8]) -> PyResult<&'a [u8]> {
        for f in &self.proxy.get_class().lock().unwrap().fields_desc {
            let (fval, remaining) = f.fieldtype.as_trait().getfield(self, s)?;
            self.fields.insert(f.name.clone(), Some(fval));
            s = remaining;
        }
        Ok(s)
    }

    /*
     * Internal function called to perform the dissection of the payload's fields
     */

    fn do_dissect_payload(&mut self, s: &[u8]) -> PyResult<()> {
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

    /*
     * Entry point for dissection.
     */

    pub fn dissect(&mut self, s: &[u8]) -> PyResult<()> {
        let s = self.do_dissect(s)?;
        self.do_dissect_payload(s)?;
        Ok(())
    }

    /*
     * Internal function to build the bytes of the current packet
     */
    fn self_build(&self) -> PyResult<Vec<u8>> {
        let mut s: Vec<u8> = Vec::new();
        for f in &self.proxy.get_class().lock().unwrap().fields_desc {
            s = f
                .fieldtype
                .as_trait()
                .addfield(self, s, &self._getfieldval(&f.name).unwrap())?;
        }
        Ok(s)
    }

    /*
     * Internal function to build the bytes of the payload
     */
    fn do_build_payload(&self) -> PyResult<Option<Vec<u8>>> {
        if let Some(payload) = &self.payload {
            Ok(Some(payload.do_build()?))
        } else {
            Ok(None)
        }
    }

    /*
     * Internal function to add the padding
     */
    fn build_padding(&self) -> PyResult<Option<Vec<u8>>> {
        Ok(None)
    }

    /*
     * Return the bytes from a packet with the payload
     */
    fn do_build(&self) -> PyResult<Vec<u8>> {
        self.post_build(self.self_build()?, self.do_build_payload()?)
    }

    /*
     * Called right after the current layer is built
     */
    #[pyo3(signature = (pkt, pay))]
    fn post_build(&self, mut pkt: Vec<u8>, pay: Option<Vec<u8>>) -> PyResult<Vec<u8>> {
        if let Some(pay) = pay {
            pkt.extend(pay);
        }
        Ok(pkt)
    }

    /*
     * Entry point for build.
     */
    fn build(&self) -> PyResult<Vec<u8>> {
        let mut p = self.do_build()?;
        if let Some(payload) = self.do_build_payload()? {
            p.extend(payload);
        }
        if let Some(padding) = self.build_padding()? {
            p.extend(padding);
        }
        Ok(p)
    }

    /*
     * Functions to set/get the '.payload' attribute and take into account the overloaded fields.
     */

    #[pyo3(signature = (payload))]
    fn add_payload(&mut self, payload: Packet) {
        if let Some(pay) = &mut self.payload {
            // We have a payload already. Add it below it
            pay.add_payload(payload);
        } else {
            // Check if that payload overloads some of our fields
            let cls = payload.proxy.get_class();
            let cls_locked = cls.lock().unwrap();
            let overloaded_fields = cls_locked._overload_fields.get(&self.proxy._uuid);
            // Add payload
            self.payload = Some(Box::new(payload));
            // If the payload does overload some of our fields, apply them
            if let Some(overloaded_fields) = overloaded_fields {
                self.overloaded_fields = overloaded_fields.clone();
            }
        }
    }
    fn remove_payload(&mut self) {
        self.payload = None;
        self.overloaded_fields.clear();
    }

    /*
     * Setter / Getter for the '.payload' attribute.
     */

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

    /*
     * Return a proxy to the field object based on it's name.
     */
    fn get_field(&self, attr: String) -> PyResult<FieldProxy> {
        self._get_field(&attr)
    }

    /*
     * Get / Set an internal field's value.
     */

    fn getfieldval(&self, attr: String) -> PyResult<Option<&types::InternalType>> {
        self._getfieldval(&attr)
    }

    #[pyo3(signature = (attr, val))]
    fn setfieldval(
        &mut self,
        attr: String,
        val: Option<&pyo3::Bound<'_, pyo3::PyAny>>,
    ) -> PyResult<()> {
        let val = if let Some(val) = val {
            Some(
                self._get_field(&attr)?
                    .fieldtype
                    .as_trait()
                    .any2i(Some(self), &Some(val))?,
            )
        } else {
            None
        };
        self.fields.insert(attr, val);
        Ok(())
    }
}

/*
 * Standard binding methods. Accessed by the Python world through proxies to bind
 * together PacketClasses globally.
 */

#[pyfunction]
#[pyo3(signature = (lower, upper, **kwargs))]
pub fn bind_bottom_up<'py>(
    lower: &PacketClassProxy,
    upper: &PacketClassProxy,
    kwargs: Option<HashMap<String, Bound<'py, PyAny>>>,
) -> PyResult<()> {
    let cls = lower.get_class();
    let mut lowercls = cls.lock().unwrap();
    let mut mapped_fields = None;
    if let Some(kwargs) = kwargs {
        let kwargs_converted: Result<HashMap<String, types::InternalType>, PyErr> = kwargs
            .iter()
            .map(|(k, v)| {
                let fproxy = lowercls.get_field(k)?;
                let fval = fproxy.fieldtype.as_trait().any2i(None, &Some(v));
                if let Ok(ival) = fval {
                    Ok((k.clone(), ival))
                } else {
                    Err(PyAttributeError::new_err(
                        "Unknown field name (bind_bottom_up)",
                    ))
                }
            })
            .collect();
        mapped_fields = Some(kwargs_converted?);
    }
    lowercls
        .payload_guess
        .push((mapped_fields, upper._uuid.clone()));
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (lower, upper, **kwargs))]
pub fn bind_top_down<'py>(
    lower: &PacketClassProxy,
    upper: &PacketClassProxy,
    kwargs: Option<HashMap<String, Bound<'py, PyAny>>>,
) -> PyResult<()> {
    if let Some(kwargs) = kwargs {
        let cls = lower.get_class();
        let lowercls = cls.lock().unwrap();
        let kwargs_converted: Result<HashMap<String, types::InternalType>, PyErr> = kwargs
            .iter()
            .map(|(k, v)| {
                let fproxy = lowercls.get_field(k)?;
                let fval = fproxy.fieldtype.as_trait().any2i(None, &Some(v));
                if let Ok(ival) = fval {
                    Ok((k.clone(), ival))
                } else {
                    Err(PyAttributeError::new_err(
                        "Unknown field name (bind_top_down)",
                    ))
                }
            })
            .collect();
        let cls = upper.get_class();
        let mut uppercls = cls.lock().unwrap();
        uppercls
            ._overload_fields
            .insert(lower._uuid.clone(), kwargs_converted?);
    }
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (lower, upper, **kwargs))]
pub fn bind_layers<'py>(
    lower: &PacketClassProxy,
    upper: &mut PacketClassProxy,
    kwargs: Option<HashMap<String, Bound<'py, PyAny>>>,
) -> PyResult<()> {
    bind_bottom_up(lower, upper, kwargs.clone())?;
    bind_top_down(lower, upper, kwargs)?;
    Ok(())
}

/*
 * Add module definition into the Python world
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
