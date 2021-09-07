# This class is a pcap iterator that reads a series of packets
from .pcap_specs import PcapSpec
from .helpers import pcapReader, satisfy_timespec

class PcapTimeIterator():
    def __init__(self, spec:PcapSpec = None, files=[], timespec=None):
        if spec is not None:
            self.spec = spec
            self.files = spec.files
            self.timespec = spec.timespec
        else:
            self.spec = None
            self.files = files
            self.timespec = timespec

        self.current_file = 0 # index of iterated file
        self.file_contents = None
        self.file_itered = -1

    def __load_pkts(self, pcap):
        self.file_contents = []
        pkt_index = 0
        found_pkt = False
        for ts, buf in pcap:
            self.file_contents.append((ts, buf))
            if self.file_itered < 0:
                if satisfy_timespec(ts, self.timespec):
                    self.file_itered = pkt_index
                    found_pkt = True
            pkt_index += 1
        return found_pkt

    def __iter__(self):
        found_pkt = False
        for i in range(len(self.files)):
            pcap = pcapReader(self.files[i])
            found_pkt = self.__load_pkts(pcap)
            if found_pkt:
                self.current_file = i
                break
        return self

    def __next__(self):
        # 1: current file has remaining packet, consume this file
        if self.file_itered < len(self.file_contents):
            ret_ts, ret_buf = self.file_contents[self.file_itered]
            if satisfy_timespec(ret_ts, self.timespec):
                self.file_itered += 1
                return ret_ts, ret_buf

        # 2: We don't have enough files, stop
        if self.current_file >= len(self.files):
            raise StopIteration

        # 3: Find the next packet which satisfies the timespec from file list
        found_pkt = False
        for i in range(self.current_file+1, len(self.files)):
            pcap = pcapReader(self.files[self.current_file])
            found_pkt = self.__load_pkts(pcap)
            if found_pkt:
                self.current_file = i
                break

        print(self.spec.name, found_pkt)

        # 4: Check if we find the pkt, and return
        if not found_pkt:
            raise StopIteration
        else:
            ret_ts, ret_buf = self.file_contents[self.file_itered]
            self.file_itered += 1
            return ret_ts, ret_buf
