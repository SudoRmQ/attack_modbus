from time import sleep 
from scapy.all import *
class Modbus(Packet):
    name = "modbus"
    fields_desc = [ XByteField("Function Code", 15),   
                    ShortField("Reference Number", 0),
                    ShortField("Bit Count", 6),
                    ByteField("Byte Count", 1),
                    ByteField("Data", 0)
                    ]