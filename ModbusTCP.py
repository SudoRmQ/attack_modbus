from time import sleep 
from scapy.all import *
class ModbusTCP(Packet):
    name = "mbtcp"
    fields_desc = [ ShortField("Transaction Identifier", 1243), 
                    ShortField("Protocol Identifier", 0),
                    ShortField("Length", 8),
                    ByteField("Unit Identifier",1)
                    ]