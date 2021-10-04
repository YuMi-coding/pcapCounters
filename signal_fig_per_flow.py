#!/usr/bin/env python3
# Reads from pcap files and calculates their signals, generates the signals and calculates per flow singals

import argparse
import nest_asyncio
# Monkey patches for fix the re-entering of asyncio problem
nest_asyncio.apply()

# __import__('IPython').embed()

from multiprocessing import Pool, cpu_count
from src.sharks.session_splitter import SessionSplitter

from src.data.align import Align
from src.sharks.sharkReader import SharkReader
from src.sharks.sharkConfig import SharkConfigFactory
from src.plots.plotter import Plotter

DEBUG = 1
save_metadata = False

argparser = argparse.ArgumentParser(description="Detects the signal(rtm/ofo) from pcap files. \
    Preferablly loads the specs for legitimate/ malicious end hosts.")
argparser.add_argument("-i", "--input", help="Input pcap file")
argparser.add_argument("-s", "--spec", help="Specification for hosts, can include both types")
argparser.add_argument("-t", "--spec-type", choices=["address", "protocol"], help="The kind of spec.", default="address")
argparser.add_argument("-o", "--output", help="The output image name.", default="./default_imagename.png")
argparser.add_argument("-m", "--metadata-output", help="output the metadata of the figure", default=False, action="store_true")
# argparser.add_argument("-l", "--legitimate-hosts", help="Legitimat hosts list")
# argparser.add_argument("-m", "--malicious-hosts", help="Malicious hosts list")
# argparser.add_argument("-p", "--deep-parallel", help="Use a fast pass to split traces into smaller session-based traces\
#     and then analyze them.", default=False, action="store_true")

def get_filelist(input_filename, output_filename):
    from os import listdir
    from os.path import isfile, join, isdir
    if isdir(input_filename):
        input_filelist = [join(input_filename, f) for f in listdir(input_filename) if isfile(join(input_filename, f))]
        output_filelist = [ output_filename + f + ".png" for f in listdir(input_filename) if isfile(join(input_filename, f))]
        return zip(input_filelist, output_filelist)
    elif isfile(input_filename):
        return [(input_filename, output_filename)]
    else:
        print("Unidentified input_filename!")
        raise NotImplementedError

def process_a_pcap(arguments):
    input_file, output_file = arguments
    # global_data[input_file] = {}

    malicious_reader = SharkReader(input_file, signal_filters.malicious_filter)
    legitimate_reader = SharkReader(input_file, signal_filters.legitimate_filter)

    m_ts, m_signal = malicious_reader.get_ts_signal()
    l_ts, l_signal = legitimate_reader.get_ts_signal()

    malicious_flow_reader = SharkReader(input_file, flow_filters.malicious_filter)
    legitimate_flow_reader = SharkReader(input_file, flow_filters.legitimate_filter)

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
    plotter.linePlot(alignX=True).saveFig(output_file)
    if save_metadata:
        plotter.saveMeta(output_file)
    print("Finished processing ", output_file)


if __name__ == "__main__":
    args = argparser.parse_args()
    if [args.spec] == [None, None, None]:
        print("No available specs!")
        exit(0)

    if args.spec_type not in ["address", "protocol"]:
        raise NotImplementedError
    
    if args.metadata_output:
        save_metadata = True

    signal_filters = {
        "address"   :   SharkConfigFactory("(tcp.analysis.retransmission || tcp.analysis.out_of_order)").\
        loadSpecAddresses(args.spec).getFilter(),
        "protocol"  :   SharkConfigFactory("(tcp.analysis.retransmission || tcp.analysis.out_of_order)").\
        loadSpecProtocol(args.spec).getFilter(),
    }[args.spec_type]
    flow_filters = {
        "address"   :   SharkConfigFactory("(tcp)").loadSpecAddresses(args.spec).getFilter(),
        "protocol"  :   SharkConfigFactory("(tcp)").loadSpecProtocol(args.spec).getFilter()
    }[args.spec_type]

    if DEBUG:
        print("signal filters for malicious:\n", signal_filters.malicious_filter)
        print("signal filters for all:\n", signal_filters.legitimate_filter)
        print("flow filters for malicious:\n", flow_filters.malicious_filter)
        print("flow filters for all:\n", flow_filters.legitimate_filter)

    tasks = list(get_filelist(args.input, args.output))
    print("Available tasks: ", tasks)

    # We are not doing deep parallel for now.
    with Pool(int(cpu_count() / 2)) as pool:
        pool.map(process_a_pcap, tasks)
