#!/usr/bin/env python3
# Reads from pcap files and calculates their signals, generates the signals and calculates per flow singals

import argparse

from src.data.align import Align

from src.sharks.sharkReader import SharkReader
from src.sharks.sharkConfig import SharkConfigFactory
from src.plots.plotter import Plotter

DEBUG = 1
argparser = argparse.ArgumentParser(description="Detects the signal(rtm/ofo) from pcap files. \
    Preferablly loads the specs for legitimate/ malicious end hosts.")
argparser.add_argument("-i", "--input", help="Input pcap file")
argparser.add_argument("-s", "--spec", help="Specification for hosts, can include both types")
argparser.add_argument("-m", "--malicious-hosts", help="Malicious hosts list")
argparser.add_argument("-l", "--legitimate-hosts", help="Legitimat hosts list")
argparser.add_argument("-o", "--output", help="The output image name.", default="./default_imagename.png")


if __name__ == "__main__":
    args = argparser.parse_args()
    if [args.spec, args.malicious_hosts, args.legitimate_hosts] == [None, None, None]:
        print("No available specs!")
        exit(0)

    signal_filters = SharkConfigFactory("(tcp.analysis.retransmission || tcp.analysis.out_of_order)").\
        loadSpec(args.spec).getFilter()
    flow_filters = SharkConfigFactory("(tcp)").loadSpec(args.spec).getFilter()

    if DEBUG:
        print("signal filters for malicious:\n", signal_filters.malicious_filter)
        print("signal filters for all:\n", signal_filters.legitimate_filter)
        print("flow filters for malicious:\n", flow_filters.malicious_filter)
        print("flow filters for all:\n", flow_filters.legitimate_filter)

    malicious_reader = SharkReader(args.input, signal_filters.malicious_filter)
    legitimate_reader = SharkReader(args.input, signal_filters.legitimate_filter)

    m_ts, m_signal = malicious_reader.get_ts_signal()
    l_ts, l_signal = legitimate_reader.get_ts_signal()

    malicious_flow_reader = SharkReader(args.input, flow_filters.malicious_filter)
    legitimate_flow_reader = SharkReader(args.input, flow_filters.legitimate_filter)

    mf_ts, mf_flows = malicious_flow_reader.get_ts_flowcount()
    lf_ts, lf_flows = legitimate_flow_reader.get_ts_flowcount()
    # print(len(m_ts), len(m_signal))
    # print(len(l_ts), len(l_signal))

    l_aligned = Align(key=l_ts, value=l_signal).loadKeyValue(key=lf_ts, value=lf_flows).getDivided()
    m_aligned = Align(key=m_ts, value=m_signal).loadKeyValue(key=mf_ts, value=mf_flows).getDivided()

    plotter = Plotter(data={
            "total": {
                "x" : l_aligned.key,
                "y" : l_aligned.value,
            },
            "malicious":{
                "x" : m_aligned.key,
                "y" : m_aligned.value,
            }
        },
        x_legend="Time(s)",
        y_legend="Retransmission signals per Flow"
    )
    plotter.linePlot(alignX=True).saveFig(args.output)
