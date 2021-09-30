#!/usr/bin/env python3
# Reads from pcap files and calculates their signals
import argparse

from multiprocessing import Pool, Queue, cpu_count
from src.sharks.session_splitter import SessionSplitter

from src.sharks.sharkReader import SharkReader
from src.sharks.sharkConfig import SharkConfigFactory

from src.plots.plotter import Plotter


argparser = argparse.ArgumentParser(description="Detects the signal(rtm/ofo) from pcap files. \
    Preferablly loads the specs for legitimate/ malicious end hosts.")
argparser.add_argument("-i", "--input", help="Input pcap file")
argparser.add_argument("-s", "--spec", help="Specification for hosts, can include both types")
argparser.add_argument("-t", "--spec-type", choices=["address", "protocol"], help="The kind of spec.", default="address")
argparser.add_argument("-o", "--output", help="The output image name.", default="./default_imagename.png")
argparser.add_argument("-p", "--deep-parallel", help="Use a fast pass to split traces into smaller session-based traces\
    and then analyze them.", default=False, action="store_true")
# WIP
argparser.add_argument("-f", "--per-flow", help="Use the per flow statistics",\
    default=False, action="store_true")

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

# NOTE: Tshark does not support multithreading since it has a parsing engine
# Checkout: https://osqa-ask.wireshark.org/questions/56433/multi-threaded-tshark/

# TODO: We can further parallelize the processing of each reader, and split a single drawer

# global_queues = {}
# global_data = {}

# # class readerThread(threading.Thread):
# #     def __init__(self, reader, filename, typename):
# #         threading.Thread.__init__(self)
# #         self.reader = reader
# #         self.filename = filename
# #         self.typename = typename

# #     def run(self):
# #         ts, signal = self.reader.get_ts_signal()
# #         global_data[self.filename][self.typename] = (ts, signal)


# # def process_a_filter(arguments):
# #     pcapname, reader, type = arguments
# #     ts, signal = reader.get_ts_signal()
# #     global_data[pcapname][type] = (ts, signal)

def process_a_pcap(arguments):
    input_file, output_file = arguments
    # global_data[input_file] = {}

    malicious_reader = SharkReader(input_file, shark_filters.malicious_filter)
    legitimate_reader = SharkReader(input_file, shark_filters.legitimate_filter)

    # malicious_thread = readerThread(malicious_reader, input_file, "malicious")
    # legitimate_thread = readerThread(legitimate_reader, input_file, "legitimate")

    # threads = [malicious_thread, legitimate_thread]
    # for t in threads:
    #     t.start()
    # for t in threads:
    #     t.join()

    # m_ts, m_signal = global_data[input_file]["malicious"]
    # l_ts, l_signal = global_data[input_file]["legitimate"]
    m_ts, m_signal = malicious_reader.get_ts_signal()
    l_ts, l_signal = legitimate_reader.get_ts_signal()
    plotter = Plotter(data={
        "legitimate": {
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
    print("Finished processing ", output_file)

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

    print("Legitimate filters=",shark_filters.legitimate_filter)
    print("Malicious filters=",shark_filters.malicious_filter)

    tasks = list(get_filelist(args.input, args.output))
    print("Available tasks: ", tasks)

    if not args.deep_parallel: # parallel by pcap file
        with Pool(cpu_count() - 2) as pool:
            pool.map(process_a_pcap, tasks)
    else: # TODO: Do deep parallel operations
        for input_filename, output_filename in tasks:
            splitter = SessionSplitter(input_filename)
            splitter.split()
            exit(0)
            splitter.del_temps()

