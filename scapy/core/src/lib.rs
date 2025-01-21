/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * This file is part of Scapy
 * See https://scapy.net/ for more information
 * Copyright (C) Gabriel Potter
 */

use pyo3::prelude::*;
use pyo3::wrap_pymodule;

mod types;
mod utils;

pub mod fields;
pub mod packet;

#[pymodule]
fn core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(fields::fields))?;
    m.add_wrapped(wrap_pymodule!(packet::packet))?;
    Ok(())
}
