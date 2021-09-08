import numpy as np
import ipaddress
import pyshark
import dpkt

from . import consts

class key_v4():
    def __init__(self, pkt=None, srcIP="0.0.0.0", dstIP="0.0.0.0", srcPort=0, dstPort=0):
        self.srcIP = ipaddress.IPv4Address(srcIP)
        self.dstIP = ipaddress.IPv4Address(dstIP)
        self.srcPort = np.ushort(srcPort)
        self.dstPort = np.ushort(dstPort)
        if pkt is not None:
            self.readPkt(pkt)

    class UnknownPktTypeException(Exception):
        print("We have an unknown packet type.")
        pass

    def readPkt(self, pkt):

        if type(pkt) not in [pyshark.packet.packet.Packet, bytes]:
            print(type(pkt))
            raise self.UnknownPktTypeException

        # Use pyshark backend
        if isinstance(pkt, pyshark.packet.packet.Packet):
            self.srcIP = ipaddress.ip_address(pkt.ip.src)
            self.dstIP = ipaddress.ip_address(pkt.ip.dst)
            
            ip_proto = pkt.ip.proto
            if ip_proto == consts.IP_P_PROTO_TCP:
                self.srcPort = np.ushort(pkt.tcp.srcport)
                self.dstPort = np.ushort(pkt.tcp.dstport)
            if ip_proto == consts.IP_P_PROTO_UDP:
                self.srcPort = np.ushort(pkt.udp.srcport)
                self.dstPort = np.ushort(pkt.udp.dstport)
        
        # Use dpkt backend
        if isinstance(pkt, bytes):
            eth = dpkt.ethernet.Ethernet(pkt)
            if not isinstance(eth.data, dpkt.ip.IP):
                return 
            ip = eth.data

            if type(ip.data) not in [dpkt.tcp.TCP, dpkt.udp.UDP]:
                return
            self.srcIP = ipaddress.ip_address(ip.src)
            self.detIP = ipaddress.ip_address(ip.dst)
            
            self.srcPort = np.ushort(ip.data.sport)
            self.dstPort = np.ushort(ip.data.dport)

    def __eq__(self, other):
        return other and self.srcIP == other.srcIP and self.dstIP == other.dstIP and \
            self.srcPort == other.srcPort and self.dstPort == other.dstPort

    def __hash__(self):
        return hash((self.srcIP, self.dstIP, self.srcPort, self.dstPort))

class Flow():
    def __init__(self, flowkey, flowdata=None):
        self.flowkey = flowkey
        self.keytype = type(self.flowkey)
        self.flowdata = flowdata