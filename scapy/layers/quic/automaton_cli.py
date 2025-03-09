# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
QUIC client automaton

This is very primitive.
"""

import socket

from scapy.automaton import ATMT

from scapy.layers.quic.automaton import _QUICAutomaton

# Automata


class QUICClientAutomaton(_QUICAutomaton):
    """
    A simple QUIC client automaton. Try to overload some states or
    conditions and see what happens on the other side.

    :param server: the remote IP to connect to.
    :param dport: the UDP port to connect to (default: 443)
    :param tlsatmt: the TLSClientAutomaton instance to use for
    """

    def parse_args(self, server="127.0.0.1", dport=443, **kwargs):
        tmp = socket.getaddrinfo(server, dport)
        self.remote_family = tmp[0][0]
        self.remote_ip = tmp[0][4][0]
        self.remote_port = dport
        self.local_ip = None
        self.local_port = None
        self.socket = None
        super(QUICClientAutomaton, self).parse_args(
            server=server,
            dport=dport,
            **kwargs,
        )

    @ATMT.state(initial=True)
    def INITIAL(self):
        self.vprint("Starting QUIC client automaton.")
        raise self.INIT_TLS_SESSION()

    @ATMT.state()
    def INIT_TLS_SESSION(self):
        raise self.CONNECT()

    # Change some steps of the TLS automaton to act QUIC like

    @ATMT.state()
    def CONNECT(self):
        s = socket.socket(self.remote_family, socket.SOCK_DGRAM)
        self.vprint()
        self.vprint("Trying to connect on %s:%d" % (self.remote_ip, self.remote_port))
        s.connect((self.remote_ip, self.remote_port))
        self.socket = s
        self.local_ip, self.local_port = self.socket.getsockname()[:2]
        self.vprint()
        raise self.QUIC_START()

    # QUIC handshake
    # https://datatracker.ietf.org/doc/html/rfc9000#section-7

    @ATMT.state()
    def QUIC_START(self):
        pass

    @ATMT.condition(QUIC_START)
    def quic_should_add_Initial(self):
        
        self.add_msg(p)
        raise self.QUIC_ADDED_INITIAL()

    @ATMT.state()
    def QUIC_ADDED_INITIAL(self):
        raise self.QUIC_SENDING_INITIAL()

    @ATMT.state()
    def QUIC_SENDING_INITIAL(self):
        pass

    @ATMT.condition(QUIC_SENDING_INITIAL)
    def quic_should_send_initial(self):
        self.flush_records()
        raise self.QUIC_SENT_INITIAL()

    @ATMT.state()
    def QUIC_SENT_INITIAL(self):
        raise self.TLS13_WAITING_SERVER_HANDSHAKE()

    @ATMT.state()
    def TLS13_WAITING_SERVER_HANDSHAKE(self):
        pass

    @ATMT.receive_condition(TLS13_WAITING_SERVER_HANDSHAKE)
    def receive_quic_handshake(self, pkt):
        pass