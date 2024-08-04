# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter

"""
Simple Service Discovery Protocol

https://datatracker.ietf.org/doc/html/draft-cai-ssdp-v1-03
"""

import re

from scapy.packet import (
    bind_bottom_up,
    bind_layers,
)
from scapy.fields import (
    DestField,
    DestIP6Field,
)
from scapy.layers.http import (
    _HTTPContent,
    _HTTPHeaderField,
    _generate_headers,
    _dissect_headers,
)
from scapy.layers.inet import UDP


SSDP_HEADERS = [
    "AL",
    "Cache-Control",
    "Ext",
    "Host",
    "MX",
    "Man",
    "S",
    "ST",
    "USN",
]


class SSDP(_HTTPContent):
    name = "SSDP"
    fields_desc = (
        [
            # First line
            _HTTPHeaderField("Method", "M-SEARCH"),
            _HTTPHeaderField("Request_Uri", "*"),
            _HTTPHeaderField("Version", "SSDP/1.0"),
            # Headers
        ]
        + (
            _generate_headers(
                SSDP_HEADERS,
            )
        )
        + [
            _HTTPHeaderField("Unknown-Headers", None),
        ]
    )

    def do_dissect(self, s):
        first_line, body = _dissect_headers(self, s)
        try:
            method, uri, version = re.split(rb"\s+", first_line, maxsplit=2)
            self.setfieldval("Method", method)
            self.setfieldval("Request_Uri", uri)
            self.setfieldval("Version", version)
        except ValueError:
            pass
        if body:
            self.raw_packet_cache = s[: -len(body)]
        else:
            self.raw_packet_cache = s
        return body

    def mysummary(self):
        return self.sprintf(
            "%SSDPRequest.Method% %SSDPRequest.Request_Uri% " "%SSDPRequest.Version%"
        )


bind_bottom_up(UDP, SSDP, sport=1900)
bind_bottom_up(UDP, SSDP, dport=1900)
bind_layers(UDP, SSDP, dport=1900, sport=1900)

DestField.bind_addr(SSDP, "239.255.255.250", dport=1900)
DestIP6Field.bind_addr(SSDP, "ff02::C", dport=1900)
