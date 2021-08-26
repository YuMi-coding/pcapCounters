#!/usr/bin/env python3
# Reads from pcap files and calculates their signals
import argparse
from re import X

from src.sharks.sharkReader import SharkReader
from src.sharks.sharkConfig import SharkConfigFactory
from src.plots.plotter import Plotter

argparser = argparse.ArgumentParser(description="Detects the signal(rtm/ofo) from pcap files. \
    Preferablly loads the specs for legitimate/ malicious end hosts.")
argparser.add_argument("-i", "--input", help="Input pcap file")
argparser.add_argument("-s", "--spec", help="Specification for hosts, can include both types")
# argparser.add_argument("-m", "--malicious-hosts", help="Malicious hosts list")
# argparser.add_argument("-l", "--legitimate-hosts", help="Legitimat hosts list")
argparser.add_argument("-o", "--output", help="The output image name.", default="./default_imagename")


if __name__ == "__main__":
    args = argparser.parse_args()
    if [args.spec] == [None]:
        print("No available specs!")
        exit(0)
    
    shark_filters = SharkConfigFactory("(tcp)").loadSpec(args.spec).getFilter()

    malicious_reader = SharkReader(args.input, shark_filters.malicious_filter)
    legitimate_reader = SharkReader(args.input, shark_filters.legitimate_filter)

    m_ts, m_pps, m_bps = malicious_reader.get_flow_rate()
    l_ts, l_pps, l_bps = legitimate_reader.get_flow_rate()

    # print(len(m_ts), len(m_signal))
    # print(len(l_ts), len(l_signal))
    # print(l_ts, l_pps)
    print("Total malicious packets: ", sum(m_pps), ", total legitimate packets:", sum(l_pps))
    print("Total malicious bytes: ", sum(m_bps), ", total legitimate byptes:", sum(l_bps))


    plotter = Plotter(data={
            "total_pps": {
                "x" : l_ts,
                "y" : l_pps,
            },
            "malicious_pps":{
                "x" : m_ts,
                "y" : m_pps,
            },
        },
        x_legend="Time(s)",
        y_legend="Packet per seconds"
    )

    plotter.linePlot(alignX=True).saveFig(args.output + "pps.png")

    plotter = Plotter(data = {
                "total_bps": {
                "x" : l_ts,
                "y" : l_bps,
            },            
            "malicious_bps":{
                "x" : m_ts,
                "y" : m_bps,
            },
        },
        x_legend = "Time(s)",
        y_legend="Bytes per seconds"
    )
    plotter.linePlot(alignX=True).saveFig(args.output + "bps.png")
