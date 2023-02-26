use pyo3::prelude::*;

use crate::utils::r#struct;

#[pyclass(subclass, module = "scapy.core.fields")]
struct Field {
    // Python fields
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    fmt: String,
    #[pyo3(get)]
    default: PyObject,
    #[pyo3(get)]
    sz: usize,
    // Rust specific fields
    core: bool,
}

#[pymethods]
impl Field {
    #[new]
    fn new(name: String, default: PyObject, fmt: Option<String>) -> PyResult<Self> {
        let fmt = fmt.unwrap_or(String::from("H")); // fmt defaults to H
        let fmt =
            if let Some('@') | Some('=') | Some('<') | Some('>') | Some('!') = fmt.chars().next() {
                // if fmt starts with "@=<>!
                fmt
            } else {
                // else: default to network
                '!'.to_string() + &fmt
            };
        Ok(Field {
            name: name,
            default,
            sz: r#struct::calcsize(&fmt)?,
            fmt: fmt,
            core: true,
        })
    }
    fn i2len(&self, _pkt: &PyAny, _x: &PyAny) -> usize {
        self.sz
    }
    fn i2count(&self, _pkt: &PyAny, _x: &PyAny) -> usize {
        1
    }
    fn h2i<'a>(&self, _pkt: &PyAny, x: &'a PyAny) -> &'a PyAny {
        x
    }
    fn i2h<'a>(&self, _pkt: &PyAny, x: &'a PyAny) -> &'a PyAny {
        x
    }
    fn m2i<'a>(&self, _pkt: &PyAny, x: &'a PyAny) -> &'a PyAny {
        x
    }
    fn i2m<'a>(&self, _pkt: &PyAny, x: &'a PyAny) -> &'a PyAny {
        x
    }
    fn any2i(slf: &PyCell<Self>, pkt: PyObject, x: PyObject) -> PyResult<PyObject> {
        slf.call_method1("h2i", (pkt, x))?.extract()
    }
    fn any2i2<'a>(&self, pkt: &PyAny, x: &'a PyAny) -> &'a PyAny {
        self.h2i(pkt, x)
    }
    fn any2i3<'a>(slf: PyRef<'a, Self>, pkt: &PyAny, x: &'a PyAny) -> PyResult<PyRef<'a, Self>> {
        slf.h2i(pkt, x).extract()
    }
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
