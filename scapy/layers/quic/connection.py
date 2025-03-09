# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
QUIC connection handler.
"""

from scapy.packet import Packet
from scapy.layers.inet import UDP

# RFC 9000 sect 5 - Connections
# https://datatracker.ietf.org/doc/html/rfc9000#name-connections


class quicConnection(object):
    def __init__(self):
        pass


class _GenericQUICConnectionInheritance(Packet):
    """
    Many classes inside the QUIC module need to get access to connection-related
    information. To this end, various QUIC objects inherit from the present class.
    """

    __slots__ = ["quic_connection"]
    name = "Dummy Generic QUIC Packet"

    def __init__(self, _pkt="", quic_connection=None, **kwargs):
        try:
            setme = self.quic_connection is None
        except Exception:
            setme = True

        if setme:
            if quic_connection is None:
                self.quic_connection = quicConnection()
            else:
                self.quic_connection = quic_connection

        Packet.__init__(self, _pkt=_pkt, **kwargs)
