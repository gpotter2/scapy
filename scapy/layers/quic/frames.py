# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
QUIC Frame Types per RFC9000 sect 19
"""

from scapy.fields import (
    ByteEnumField,
)
from scapy.packet import Packet

# RFC9000 table 3
_quic_payloads = {
    0x00: "PADDING",
    0x01: "PING",
    0x02: "ACK",
    0x04: "RESET_STREAM",
    0x05: "STOP_SENDING",
    0x06: "CRYPTO",
    0x07: "NEW_TOKEN",
    0x08: "STREAM",
    0x10: "MAX_DATA",
    0x11: "MAX_STREAM_DATA",
    0x12: "MAX_STREAMS",
    0x14: "DATA_BLOCKED",
    0x15: "STREAM_DATA_BLOCKED",
    0x16: "STREAMS_BLOCKED",
    0x18: "NEW_CONNECTION_ID",
    0x19: "RETIRE_CONNECTION_ID",
    0x1A: "PATH_CHALLENGE",
    0x1B: "PATH_RESPONSE",
    0x1C: "CONNECTION_CLOSE",
    0x1E: "HANDSHAKE_DONE",
}


# RFC9000 sect 19.1
class QUIC_PADDING(Packet):
    fields_desc = [
        ByteEnumField("Type", 0x00, _quic_payloads),
    ]


# RFC9000 sect 19.2
class QUIC_PING(Packet):
    fields_desc = [
        ByteEnumField("Type", 0x01, _quic_payloads),
    ]


# RFC9000 sect 19.3
class QUIC_ACK(Packet):
    fields_desc = [
        ByteEnumField("Type", 0x02, _quic_payloads),
    ]
