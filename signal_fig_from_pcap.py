#!/usr/bin/env python3
# Reads from pcap files and calculates their signals
import argparse

from src.sharks.sharkReader import SharkReader
from src.sharks.sharkConfig import SharkConfigFactory
from src.plots.plotter import Plotter

argparser = argparse.ArgumentParser(description="Detects the signal(rtm/ofo) from pcap files. \
    Preferablly loads the specs for legitimate/ malicious end hosts.")
argparser.add_argument("-i", "--input", help="Input pcap file")
argparser.add_argument("-s", "--spec", help="Specification for hosts, can include both types")
argparser.add_argument("-t", "--spec-type", choices=["address", "protocol"], help="The kind of spec.", default="address")
argparser.add_argument("-o", "--output", help="The output image name.", default="./default_imagename.png")

def get_filelist(input_filename, output_filename):
    from os import listdir
    from os.path import isfile, join, isdir
    if isdir(input_filename):
        input_filelist = [join(input_filename, f) for f in listdir(input_filename) if isfile(join(input_filename, f))]
        output_filelist = [ output_filename + f for f in listdir(input_filename) if isfile(join(input_file, f))]
        return zip(input_filelist, output_filelist)
    elif isfile(input_filename):
        return (input_filename, output_filename)
    else:
        print("Unidentified input_filename!")
        raise NotImplementedError

if __name__ == "__main__":
    args = argparser.parse_args()
    if [args.spec] == [None]:
        print("No available specs!")
        exit(0)

    if args.spec_type not in ["address", "protocol"]:
        raise NotImplementedError

    shark_filters = {
        "address": SharkConfigFactory("(tcp.analysis.retransmission || tcp.analysis.out_of_order)").\
            loadSpecAddresses(args.spec).getFilter(),
        "protocol": SharkConfigFactory("(tcp.analysis.retransmission || tcp.analysis.out_of_order)").\
            loadSpecProtocol(args.spec).getFilter(),
    }[args.spec_type]

    for input_file, output_file in get_filelist(args.input, args.output):
        malicious_reader = SharkReader(input_file, shark_filters.malicious_filter)
        legitimate_reader = SharkReader(input_file, shark_filters.legitimate_filter)

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
        plotter.linePlot(alignX=True).saveFig(output_file)
