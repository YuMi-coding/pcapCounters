import pyshark
from .sharkConfig import SharkConfigFactory

class SharkReader():
    def __init__(self, pcap_file, filter, time_grain = 1) -> None:
        self.pcap_file = pcap_file
        self.filter_str = filter
        self.time_grain = time_grain
        self.capture = pyshark.FileCapture(self.pcap_file, display_filter=self.filter_str)

    def refreshCapture(self):
        self.capture = pyshark.FileCapture(self.pcap_file, display_filter=self.filter_str)

    def get_ts_signal(self):
        min_ts = float(self.capture[0].frame_info.time_epoch)
        ts = [min_ts]
        signal = [0]

        max_grain = 0
        for pkt in self.capture:
            real_ts = float(pkt.frame_info.time_epoch)
            relative_ts = real_ts - min_ts

            current_grain = int(relative_ts / self.time_grain)
            if current_grain > max_grain:
                max_grain = current_grain
                ts.append(real_ts)
                signal.append(1)
            else:
                signal[-1] += 1

        return ts, signal
