from scapy.main import interact
from scapy.all import *
# Very temp
import scapy.core
from scapy.core import packet,fields,types

a = fields.ByteField.new("pc1a", types.InternalType.Byte(0))
b = fields.ByteField.new("pc1b", types.InternalType.Byte(0))
PC1 = packet.PacketClassProxy(fields_desc=[a, b])

a = fields.ByteField.new("pc2a", types.InternalType.Byte(0))
b = fields.ByteField.new("pc2b", types.InternalType.Byte(0))
PC2 = packet.PacketClassProxy(fields_desc=[a, b])

a = fields.ByteField.new("pc3a", types.InternalType.Byte(0))
b = fields.ByteField.new("pc3b", types.InternalType.Byte(0))
PC3 = packet.PacketClassProxy(fields_desc=[a, b])

packet.bind_layers(PC1, PC2, a=types.InternalType.Byte(0))
packet.bind_layers(PC1, PC3, a=types.InternalType.Byte(1))

interact(mydict=globals())
