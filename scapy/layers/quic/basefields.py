# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
QUIC special fields, use for dissection/building.

Implements:
- RFC 9000 section 16 - Variable-Length Integer Encoding
"""

import struct

from scapy.fields import (
    _EnumField,
    BitField,
    ByteField,
    EnumField,
    Field,
    FieldLenField,
    IntField,
    MultipleTypeField,
    ShortField,
    ThreeBytesField,
)
from scapy.packet import Packet

# Typing imports
from typing import (
    Any,
    Optional,
    Tuple,
)


# RFC9000 sect 16
class QuicVarIntField(Field[int, int]):
    def addfield(self, pkt: Packet, s: bytes, val: Optional[int]):
        val = self.i2m(pkt, val)
        if val < 0 or val > 0x3FFFFFFFFFFFFFFF:
            raise struct.error("requires 0 <= number <= 4611686018427387903")
        if val < 0x40:
            return s + struct.pack("!B", val)
        elif val < 0x4000:
            return s + struct.pack("!H", val | 0x4000)
        elif val < 0x40000000:
            return s + struct.pack("!I", val | 0x80000000)
        else:
            return s + struct.pack("!Q", val | 0xC000000000000000)

    def getfield(self, pkt: Packet, s: bytes) -> Tuple[bytes, int]:
        length = (s[0] & 0xC0) >> 6
        if length == 0:
            return s[1:], struct.unpack("!B", s[:1])[0] & 0x3F
        elif length == 1:
            return s[2:], struct.unpack("!H", s[:2])[0] & 0x3FFF
        elif length == 2:
            return s[4:], struct.unpack("!I", s[:4])[0] & 0x3FFFFFFF
        elif length == 3:
            return s[8:], struct.unpack("!Q", s[:8])[0] & 0x3FFFFFFFFFFFFFFF
        else:
            raise Exception("Impossible.")


class QuicVarLenField(FieldLenField, QuicVarIntField):
    pass


class QuicVarEnumField(QuicVarIntField, _EnumField[int]):
    __slots__ = EnumField.__slots__

    def __init__(self, name, default, enum):
        # type: (str, Optional[int], Any, int) -> None
        _EnumField.__init__(self, name, default, enum)  # type: ignore
        QuicVarIntField.__init__(self, name, default)

    def any2i(self, pkt, x):
        # type: (Optional[Packet], Any) -> int
        return _EnumField.any2i(self, pkt, x)  # type: ignore

    def i2repr(
        self,
        pkt,  # type: Optional[Packet]
        x,  # type: int
    ):
        # type: (...) -> Any
        return _EnumField.i2repr(self, pkt, x)


# Convenience fields for QUIC packets


class _QuicEncryptedField:
    def i2repr(self, pkt, x):
        rep = super(_QuicEncryptedField, self).i2repr(pkt, x)
        if not pkt.quic_connection.decrypted:
            return "%s (encrypted)" % rep
        return rep


class _QuicPacketNumberField(_QuicEncryptedField, MultipleTypeField):
    """
    The 'PacketNumber' field.
    """

    def __init__(self, name, default):
        super(_QuicPacketNumberField, self).__init__(
            [
                (
                    ByteField(name, default),
                    (
                        lambda pkt: pkt.PacketNumberLen == 0,
                        lambda _, val: val < 0x100,
                    ),
                ),
                (
                    ShortField(name, default),
                    (
                        lambda pkt: pkt.PacketNumberLen == 1,
                        lambda _, val: val < 0x10000,
                    ),
                ),
                (
                    ThreeBytesField(name, default),
                    (
                        lambda pkt: pkt.PacketNumberLen == 2,
                        lambda _, val: val < 0x1000000,
                    ),
                ),
                (
                    IntField(name, default),
                    (
                        lambda pkt: pkt.PacketNumberLen == 3,
                        lambda _, val: val < 0x100000000,
                    ),
                ),
            ],
            ByteField(name, default),
        )


class _QuicReservedBitField(_QuicEncryptedField, BitField):
    pass


class _QuicPacketNumberBitFieldLenField(_QuicEncryptedField, BitField):
    """
    A 2-bit field that takes the value of the length of 'PacketNumber'.
    """

    def i2m(self, pkt, x):
        if x is None and pkt is not None:
            PacketNumber = pkt.PacketNumber or 0
            if PacketNumber < 0 or PacketNumber > 0xFFFFFFFF:
                raise struct.error("requires 0 <= number <= 0xFFFFFFFF")
            if PacketNumber < 0x100:
                return 0
            elif PacketNumber < 0x10000:
                return 1
            elif PacketNumber < 0x1000000:
                return 2
            else:
                return 3
        elif x is None:
            return 0
        return x
