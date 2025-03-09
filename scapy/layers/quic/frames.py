# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
QUIC Frame Types per RFC9000 sect 19
"""

from scapy.fields import (
    ByteEnumField,
    PacketListField,
    StrLenField,
)
from scapy.packet import Packet, Raw

from scapy.layers.quic.basefields import QuicVarIntField
from scapy.layers.quic.connection import _GenericQUICConnectionInheritance

# Typing imports
from typing import (
    Any,
    Tuple,
)

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

################
# Common utils #
################


class _QUIC_Frame(Packet):
    fields_desc = [
        ByteEnumField("Type", 0x00, _quic_payloads),
    ]

    # Auto-register frames

    _quic_frames_types = {}

    @classmethod
    def register_variant(cls):
        cls._quic_frames_types[cls.Type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            Type = _pkt[0]
            return cls._quic_frames_types.get(Type, cls)
        return cls


class _QUICFramesField(PacketListField):
    """
    Contains the list of 'Packet Payload' specified in multiple QUIC packets.
    (RFC9000 sect 17)
    """

    def __init__(self, name, default):
        super(_QUICFramesField, self).__init__(
            name,
            default,
            _QUIC_Frame,
        )

    def getfield(
        self,
        pkt,  # type: Packet
        s,  # type: bytes
    ):
        # type: (...) -> Tuple[bytes, Any]
        if not pkt.quic_connection.decrypted:
            return b"", _QUICEncryptedFrame(s)
        return super(_QUICFramesField, self).getfield(pkt, s)


class _QUICEncryptedFrame(Raw, _GenericQUICConnectionInheritance):
    """
    When the content of a QUIC frames could not be deciphered, we use this class to
    represent the encrypted data.
    """

    name = "Encrypted Content"
    match_subclass = True


#########################
# Frames implementation #
#########################


# RFC9000 sect 19.1
class QUIC_PADDING(_QUIC_Frame):
    Type = 0x00


# RFC9000 sect 19.2
class QUIC_PING(_QUIC_Frame):
    Type = 0x01


# RFC9000 sect 19.3
class QUIC_ACK(Packet):
    # TODO
    pass


# RFC9000 sect 19.4
class QUIC_RESET_STREAM(_QUIC_Frame):
    Type = 0x04
    fields_desc = [
        _QUIC_Frame,
        QuicVarIntField("StreamId", 0),
        QuicVarIntField("AppProtoErr", 0),
        QuicVarIntField("FinalSize", 0),
    ]


# RFC9000 sect 19.5
class QUIC_STOP_SENDING(_QUIC_Frame):
    Type = 0x05
    fields_desc = [
        _QUIC_Frame,
        QuicVarIntField("StreamId", 0),
        QuicVarIntField("AppProtoErr", 0),
    ]


# RFC9000 sect 19.6
class QUIC_CRYPTO(_QUIC_Frame):
    Type = 0x06
    fields_desc = [
        _QUIC_Frame,
        QuicVarIntField("Offset", 0),
        QuicVarIntField("Length", 0),
        StrLenField("Data", b"", length_from=lambda pkt: pkt.Length),
    ]
