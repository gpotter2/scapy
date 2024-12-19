from scapy.main import interact
from scapy.all import *
# Very temp
import scapy.core
from scapy.core import packet,fields

# RUST
a = fields.ByteField.new("pc1a", 0)
b = fields.ByteField.new("pc1b", 0)
PC1 = packet.PacketClassProxy("PC1", fields_desc=[a, b])

a = fields.ByteField.new("pc2a", 0)
b = fields.ByteField.new("pc2b", 0)
PC2 = packet.PacketClassProxy("PC2", fields_desc=[a, b])

a = fields.ByteField.new("pc3a", 0)
b = fields.ByteField.new("pc3b", 0)
PC3 = packet.PacketClassProxy("PC3", fields_desc=[a, b])

packet.bind_layers(PC1, PC2, pc1a=0)
packet.bind_layers(PC1, PC3, pc1a=1)

# Python

class PPC1(Packet):
    fields_desc = [
        ByteField("pc1a", 0),
        ByteField("pcb", 0),
    ]


class PPC2(Packet):
    fields_desc = [
        ByteField("pc2a", 0),
        ByteField("pc2b", 0),
    ]


class PPC3(Packet):
    fields_desc = [
        ByteField("pc3a", 0),
        ByteField("pc3b", 0),
    ]

bind_layers(PPC1, PPC2, pc1a=0)
bind_layers(PPC1, PPC3, pc1a=1)

interact(mydict=globals())

