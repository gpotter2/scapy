# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
The _QUICAutomaton class provides methods common to both TLS client and server.
"""

from scapy.automaton import Automaton
from scapy.config import conf
from scapy.error import log_interactive


class _QUICAutomaton(Automaton):
    def vprint(self, s=""):
        if self.verbose:
            if conf.interactive:
                log_interactive.info("> %s", s)
            else:
                print("> %s" % s)
