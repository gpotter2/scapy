# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Gabriel Potter <gabriel[]potter[]fr>

"""Generate the ethertypes file (/etc/ethertypes) based on the OpenBSD source
https://github.com/openbsd/src/blob/master/sys/net/ethertypes.h

It allows to have a file with the format of
http://git.netfilter.org/ebtables/plain/ethertypes
but up-to-date.
"""

import re
import urllib.request

from scapy.error import log_loading

URL = "https://raw.githubusercontent.com/openbsd/src/master/sys/net/ethertypes.h"  # noqa: E501

with urllib.request.urlopen(URL) as stream:
    DATA = stream.read()

reg = r".*ETHERTYPE_([^\s]+)\s.0x([0-9A-Fa-f]+).*\/\*(.*)\*\/"
COMPILED = ""
ALIASES = {
    b"IP": b"IPv4",
    b"IPV6": b"IPv6"
}

for line in DATA.split(b"\n"):
    try:
        match = re.match(reg, line.decode("utf_8", errors="backslashreplace"))
        if match:
            name = match.group(1)
            name = ALIASES.get(name, name)
            number = match.group(2)
            comment = match.group(3).strip()
            COMPILED += "    0x%s: (%s, %s),\n" % (number, repr(name), repr(comment))
    except Exception:
        log_loading.warning("Couldn't parse one line from [%s] [%r]",
                            filename, line, exc_info=True)

with open("../libs/ethertypes.py", "rb") as inp:
    data = inp.read()

with open("../libs/ethertypes.py", "wb") as out:
    ini, sep, _ = data.partition(b"DATA = {")
    COMPILED = ini + sep + b"\n" + COMPILED.encode() + b"}\n"
    print("Written: %s" % out.write(COMPILED))
