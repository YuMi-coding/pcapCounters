import numpy as np
import ipaddress

class key_v4():
    def __init__(self, srcIP="0.0.0.0", dstIP="0.0.0.0", srcPort=0, dstPort=0):
        self.srcIP = ipaddress.IPv4Address(srcIP)
        self.dstIP = ipaddress.IPv4Address(dstIP)
        self.srcPort = np.ushort(srcPort)
        self.dstPort = np.ushort(dstPort)

    def __eq__(self, other):
        return other and self.srcIP == other.srcIP and self.dstIP == other.dstIP and \
            self.srcPort == other.srcPort and self.dstPort == other.dstPort

    def __hash__(self):
        return hash((self.srcIP, self.dstIP, self.srcPort, self.dstPort))

class Flow():
    def __init__(self, flowkey, flowdata):
        self.flowkey = flowkey
        self.keytype = type(self.flowkey)
        self.flowdata = flowdata