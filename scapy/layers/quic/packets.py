# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""
QUIC Packet formats per RFC9000 sect 17
"""

from scapy.packet import (
    bind_bottom_up,
    bind_layers,
)
from scapy.fields import (
    BitEnumField,
    BitField,
    FieldLenField,
    FieldListField,
    IntField,
    StrLenField,
)
from scapy.layers.inet import UDP

from scapy.layers.quic.basefields import (
    _QuicPacketNumberBitFieldLenField,
    _QuicPacketNumberField,
    _QuicReservedBitField,
    QuicVarIntField,
    QuicVarLenField,
)
from scapy.layers.quic.connection import _GenericQUICConnectionInheritance
from scapy.layers.quic.frames import _QUICFramesField


# -- Headers --


# RFC9000 sect 17.2
_quic_long_hdr = {
    0: "Short",
    1: "Long",
}

_quic_long_pkttyp = {
    # RFC9000 table 5
    0x00: "Initial",
    0x01: "0-RTT",
    0x02: "Handshake",
    0x03: "Retry",
}

# RFC9000 sect 17 abstraction


class QUIC(_GenericQUICConnectionInheritance):
    """
    Generic QUIC packet. This implements all formats specified in RFC9000 sect 17.

    .pre_dissect() performs data decryption, .post_build() performs encryption.
    """

    match_subclass = True

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        Returns the right class for the given data.
        """
        if _pkt:
            hdr = _pkt[0]
            if hdr & 0x80:
                # Long Header packets
                if hdr & 0x40 == 0:
                    return QUIC_Version
                else:
                    typ = (hdr & 0x30) >> 4
                    return {
                        0: QUIC_Initial,
                        1: QUIC_0RTT,
                        2: QUIC_Handshake,
                        3: QUIC_Retry,
                    }[typ]
            else:
                # Short Header packets
                return QUIC_1RTT
        return QUIC_Initial

    def mysummary(self):
        return self.name

    def post_build(self, pkt, pay):
        """
        Apply encryption if necessary.
        """
        return pkt + pay


# RFC9000 sect 17.2.1


class QUIC_Version(QUIC):
    name = "QUIC - Version Negotiation"
    fields_desc = [
        BitEnumField("HeaderForm", 1, 1, _quic_long_hdr),
        BitField("Unused", 0, 7),
        IntField("Version", 0),
        FieldLenField("DstConnIDLen", None, length_of="DstConnID", fmt="B"),
        StrLenField("DstConnID", "", length_from=lambda pkt: pkt.DstConnIDLen),
        FieldLenField("SrcConnIDLen", None, length_of="SrcConnID", fmt="B"),
        StrLenField("SrcConnID", "", length_from=lambda pkt: pkt.SrcConnIDLen),
        FieldListField("SupportedVersions", [], IntField("", 0)),
    ]


# RFC9000 sect 17.2.2


class QUIC_Initial(QUIC):
    name = "QUIC - Initial"
    Version = 0x00000001
    fields_desc = (
        [
            BitEnumField("HeaderForm", 1, 1, _quic_long_hdr),
            BitField("FixedBit", 1, 1),
            BitEnumField("LongPacketType", 0, 2, _quic_long_pkttyp),
            _QuicReservedBitField("Reserved", 0, 2),
            _QuicPacketNumberBitFieldLenField("PacketNumberLen", None, 2),
        ]
        + QUIC_Version.fields_desc[2:7]
        + [
            QuicVarLenField("TokenLen", None, length_of="Token"),
            StrLenField("Token", "", length_from=lambda pkt: pkt.TokenLen),
            QuicVarIntField("Length", 0),
            _QuicPacketNumberField("PacketNumber", 0),
            _QUICFramesField("Payload", []),
        ]
    )


# RFC9000 sect 17.2.3
class QUIC_0RTT(QUIC):
    name = "QUIC - 0-RTT"
    LongPacketType = 1
    fields_desc = QUIC_Initial.fields_desc[:10] + [
        QuicVarIntField("Length", 0),
        _QuicPacketNumberField("PacketNumber", 0),
        _QUICFramesField("Payload", []),
    ]


# RFC9000 sect 17.2.4
class QUIC_Handshake(QUIC):
    name = "QUIC - Handshake"
    LongPacketType = 2
    fields_desc = QUIC_0RTT.fields_desc


# RFC9000 sect 17.2.5
class QUIC_Retry(QUIC):
    name = "QUIC - Retry"
    LongPacketType = 3
    Version = 0x00000001
    fields_desc = (
        QUIC_Initial.fields_desc[:3]
        + [
            BitField("Unused", 0, 4),
        ]
        + QUIC_Version.fields_desc[2:7]
    )


# RFC9000 sect 17.3
class QUIC_1RTT(QUIC):
    name = "QUIC - 1-RTT"
    fields_desc = [
        BitEnumField("HeaderForm", 0, 1, _quic_long_hdr),
        BitField("FixedBit", 1, 1),
        BitField("SpinBit", 0, 1),
        _QuicReservedBitField("Reserved", 0, 2),
        BitField("KeyPhase", 0, 1),
        _QuicPacketNumberBitFieldLenField("PacketNumberLen", None, 2),
        # FIXME - Destination Connection ID
        _QuicPacketNumberField("PacketNumber", 0),
        _QUICFramesField("Payload", []),
    ]


# Bindings
bind_bottom_up(UDP, QUIC, dport=443)
bind_bottom_up(UDP, QUIC, sport=443)
bind_layers(UDP, QUIC, dport=443, sport=443)
