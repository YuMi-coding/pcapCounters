#!/usr/bin/env python3
# Reads from pcap files and calculates their signals, generates the signals and calculates per flow singals

import argparse

from .sharks.sharkReader import SharkReader
from .sharks.sharkConfig import SharkConfigFactory
from .plots.plotter import Plotter

argparser = argparse.ArgumentParser(description="Detects the signal(rtm/ofo) from pcap files. \
    Preferablly loads the specs for legitimate/ malicious end hosts.")
argparser.add_argument("-i", "--input", help="Input pcap file")
argparser.add_argument("-s", "--spec", help="Specification for hosts, can include both types")
argparser.add_argument("-m", "--malicious-hosts", help="Malicious hosts list")
argparser.add_argument("-l", "--legitimate-hosts", help="Legitimat hosts list")


if __name__ == "__main__":
    args = argparser.parse_args()
    if [args.spec, args.malicious_hosts, args.legitimate_hosts] == [None, None, None]:
        print("No available specs!")
        exit(0)
    
    shark_filters = SharkConfigFactory("(tcp.analysis.retransmission || tcp.analysis.out_of_order)").\
        loadSpec(args.spec).getFilter()

    malicious_reader = SharkReader(args.input, shark_filters.malicious_filter)
    legitimate_reader = SharkReader(args.input, shark_filters.legitimate_filter)

    m_ts, m_signal = malicious_reader.get_ts_signal()
    l_ts, l_signal = legitimate_reader.get_ts_signal()

    # print(len(m_ts), len(m_signal))
    # print(len(l_ts), len(l_signal))

    plotter = Plotter(data={
            "total": {
                "x" : l_ts,
                "y" : l_signal,
            },
            "malicious":{
                "x" : m_ts,
                "y" : m_signal,
            }
        },
        x_legend="Time(s)",
        y_legend="Retransmission signals"
    )
    plotter.linePlot(alignX=True).saveFig("./test.png")
