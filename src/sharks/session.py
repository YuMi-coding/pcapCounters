# Defines a TCP session
import numpy as np
import ipaddress
from .flow import key_v4

class session_v4():
    '''
        Defines a session in ipv4 space, could be any ip-based protocol
        A session is defined as [srcip, srcport] <-> [dstip, dstport],
        but here we *manually* makes the srcip to be smaller than dstip 
        so that this struct is easier for sorting
    '''
    def __init__(self, pkt=None, srcIP="0.0.0.0", dstIP="0.0.0.0", srcPort=0, dstPort=0):
        self.srcIP = ipaddress.IPv4Address(srcIP)
        self.dstIP = ipaddress.IPv4Address(dstIP)
        self.srcPort = np.ushort(srcPort)
        self.dstPort = np.ushort(dstPort)
        if pkt is not None:
            self.readPkt(pkt)
        self.to_session()

    # Uses the flow key to parse a packet into session
    def readPkt(self, pkt):
        pkt_key = key_v4(pkt)
        self.srcIP = pkt_key.srcIP
        self.dstIP = pkt_key.dstIP
        self.srcPort = pkt_key.srcPort
        self.dstPort = pkt_key.dstPort

    # Switch the src/dst if the order is wrong
    def to_session(self):
        if self.srcIP > self.dstIP:
            self.srcIP, self.srcPort, self.dstIP, self.dstPort = \
                self.dstIP, self.dstPort, self.srcIP, self.srcPort

    def __hash__(self) -> int:
        return hash((self.srcIP, self.dstIP, self.srcPort, self.dstPort))