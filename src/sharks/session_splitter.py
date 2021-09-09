import os
import dpkt

from multiprocessing import Pool, cpu_count
from .session import session_v4

SPLITTER_WRITE_THRES = 10000

class SessionSplitter():
    """
        Splits a pcap file according to the session of it
        Args:
            pcapfile    : the pcap file
            temp_folder : the temporary folder to hold all pcaps
    """
    def __init__(self, pcapfile, temp_folder="./temp"):
        self.pcapfile = pcapfile
        self.temp_folder = temp_folder
        self.sessions = set()

    def preprocess_spilt(self):
        pcap_fd = open(self.pcapfile, 'rb')
        reader = dpkt.pcap.Reader(pcap_fd)
        for _, buf in reader:
            this_session = session_v4(buf)
            self.sessions.add(this_session)
        return self

    def ready_temp_folder(self):
        if not os.path.isdir(self.temp_folder):
            os.mkdir(self.temp_folder)
        return self

    def session_to_pcap(self, session):
        out_filename = os.path.join(self.temp_folder, str(session) + '.pcap')

        reader = dpkt.pcap.Reader(open(self.pcapfile, "rb"))
        writer_fd = open(out_filename, "wb")
        writer = dpkt.pcap.Writer(writer_fd)

        buffer = []
        record = 0
        for ts, buf in reader:
            this_session = session_v4(buf)
            if this_session == session:
                buffer.append((ts, buf))
                record += 1
                if record > SPLITTER_WRITE_THRES:
                    for ts, buf in buffer:
                        writer.writepkt(pkt=buf, ts=ts)
                    writer_fd.flush()
                    del buffer
                    buffer = []
                    record = 0


    def split(self):
        if len(self.sessions) <= 0:
            self.preprocess_spilt()
        self.ready_temp_folder()

        with Pool(cpu_count -2) as pool:
            pool.map(self.session_to_pcap, list(self.sessions))

    def del_temps(self):
        from os import listdir
        from os.path import isfile, join
        file_lists = [join(self.temp_folder, f) for f in listdir(self.temp_folder) if isfile(join(self.temp_folder, f))]
        for file in file_lists:
            os.remove(file)
