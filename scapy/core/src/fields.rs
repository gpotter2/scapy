use pyo3::prelude::*;

use crate::packet;
use crate::utils::r#struct;

pub trait Field<I> {
    fn i2len(&self, pkt: packet::Packet, x: &I) -> usize;
    fn i2count(&self, pkt: packet::Packet, x: &I) -> usize;
    fn m2i(&self, pkt: packet::Packet, x: &[u8]) -> Result<I, &str>;
    fn i2m(&self, pkt: packet::Packet, x: &I) -> Result<&[u8], &str>;
}

struct RustField<I> {
    name: String,
    fmt: String,
    default: I,
    sz: usize,
}

impl<I> Field<I> for RustField<I> {
    fn new(name: String, default: PyObject, fmt: Option<String>) -> Result<Self, &'static str> {
        let fmt = fmt.unwrap_or(String::from("H")); // fmt defaults to H
        let fmt =
            if let Some('@') | Some('=') | Some('<') | Some('>') | Some('!') = fmt.chars().next() {
                // if fmt starts with "@=<>!
                fmt
            } else {
                // else: default to network
                '!'.to_string() + &fmt
            };
        Ok(RustField {
            name: name,
            default,
            sz: r#struct::calcsize(&fmt)?,
            fmt: fmt,
        })
    }

    // fn i2len(&self, _pkt: &PyAny, _x: &I) -> usize {
    //     self.sz
    // }
    // fn i2count(&self, _pkt: &PyAny, _x: &PyAny) -> usize {
    //     1
    // }
    // fn h2i<'a>(&self, _pkt: &PyAny, x: &'a PyAny) ->  {
    //     x
    // }
    // fn i2h<'a>(&self, _pkt: &PyAny, x: &'a PyAny) -> &'a PyAny {
    //     x
    // }
    // fn m2i<'a>(&self, _pkt: &PyAny, x: &'a PyAny) -> &'a PyAny {
    //     x
    // }
    // fn i2m<'a>(&self, _pkt: &PyAny, x: &'a PyAny) -> &'a PyAny {
    //     x
    // }
    // fn any2i<'a>(&self, pkt: &PyAny, x: &'a PyAny) -> &'a PyAny {
    //     self.h2i(pkt, x)
    // }
    fn i2len(&self, pkt: packet::Packet, x: &I) -> usize {
        self.sz
    }
    fn i2count(&self, pkt: packet::Packet, x: &I) -> usize {
        1
    }
    fn m2i(&self, pkt: packet::Packet, x: &[u8]) -> Result<I, &str> {

    }
    fn i2m(&self, pkt: packet::Packet, x: &I) -> Result<&[u8], &str> {
        
    }
}

#[pyclass(subclass, module = "scapy.core.fields")]
struct ScapyField {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    fmt: String,
    #[pyo3(get)]
    default: PyObject,
    #[pyo3(get)]
    sz: usize,
}

#[pymethods]
impl ScapyField {
    fn i2repr(slf: &PyCell<Self>, pkt: PyObject, x: PyObject) -> PyResult<String> {
        PyModule::import(slf.py(), "builtins")?
            .getattr("repr")?
            .call1((slf.call_method1("h2i", (pkt, x))?,))?
            .extract()
    }
}

#[pymodule]
pub fn fields(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<Field>()?;
    Ok(())
}
