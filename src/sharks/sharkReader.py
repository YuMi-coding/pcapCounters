import pyshark

from .flow import Flow, key_v4
from .sharkConfig import SharkConfigFactory

class SharkReader():
    def __init__(self, pcap_file, filter, time_grain = 1) -> None:
        self.pcap_file = pcap_file
        self.filter_str = filter
        self.time_grain = time_grain
        self.capture = pyshark.FileCapture(self.pcap_file, display_filter=self.filter_str)

    def refreshCapture(self):
        self.capture = pyshark.FileCapture(self.pcap_file, display_filter=self.filter_str)

    # The absolute timestamp output
    def get_abs_ts_signal(self):
        try:
            min_ts = float(self.capture[0].frame_info.time_epoch)
        except KeyError:
            return [], []
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

    def get_ts_signal(self):
        try:
            min_ts = float(self.capture[0].frame_info.time_epoch)
        except KeyError:
            return [], []
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

    def get_flow_rate(self):
        try:
            min_ts = float(self.capture[0].frame_info.time_epoch)
        except KeyError:
            return [], [], []

        ts = [min_ts]
        pkt_count = [0]
        byte_count = [0]
        max_grain = 0
        for pkt in self.capture:
            real_ts = float(pkt.frame_info.time_epoch)
            
            relative_ts = real_ts - min_ts
            pkt_size = int(pkt.length)
            current_grain = int(relative_ts / self.time_grain)
            if current_grain > max_grain:
                max_grain = current_grain
                ts.append(real_ts)

                pkt_count.append(1)
                byte_count.append(pkt_size)
            else:
                pkt_count[-1] += 1
                byte_count[-1] += pkt_size
            # print(ts)
            # print(pkt_count)
            # print(byte_count)


        return ts, pkt_count, byte_count

    def get_ts_flowcount(self):
        try:
            min_ts = float(self.capture[0].frame_info.time_epoch)
        except KeyError:
            return [], []

        ts = [min_ts]
        flowcount = [0]
        flow_sets = []

        max_grain = 0
        for pkt in self.capture:
            real_ts = float(pkt.frame_info.time_epoch)
            relative_ts = real_ts - min_ts

            current_grain = int(relative_ts / self.time_grain)
            if current_grain > max_grain:
                max_grain = current_grain
                ts.append(real_ts)

                flowcount.append(1)
                flow_sets = [key_v4(pkt=pkt)]
            else:
                this_key = key_v4(pkt=pkt)
                if this_key not in flow_sets:
                    flow_sets.append(this_key)
                    flowcount[-1] += 1

        return ts, flowcount
