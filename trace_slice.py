#!/usr/bin/env python3
# This script slices a folder of pcap traces according to the specifications

import argparse
from multiprocessing import Pool, Queue, cpu_count
from os import write

from src.trace.pcap_iterator import PcapTimeIterator
from src.trace.pcap_specs import group_specs
from src.trace.helpers import parse_time_spec, parse_kind_spec, write_pcap_file


parser = argparse.ArgumentParser(description="Generate the pcap files according to time\
    specification and file list.")
parser.add_argument('-t', '--input-timefile', help='The input time specification',
    metavar="PATH", default="./timespec_03_11.json")
parser.add_argument('-f', '--input-folder', help='The input pcap file folder',
    metavar="PATH", default="../DDoS-eval/CICDDoS2019/")
parser.add_argument('-o', '--output-file', help='The output file folder',
    metavar="PATH", default='./')
parser.add_argument('-k', '--kind-file', help='The kind-file list',
    metavar="PATH", default='./01_12.json')

def process_a_spec(arguments):
    dest_filename, iterator = arguments
    write_pcap_file(dest_filename, iterator)
    print("Finished writing pcap file:", dest_filename)

def process_specs(spec_list, dest_folder):
    mp_args = []
    for spec in spec_list:
        time_iterator = PcapTimeIterator(spec = spec)
        filename = dest_folder + '/' + time_iterator.spec.name + ".pcap"
        mp_args.append((filename, time_iterator))

    with Pool(cpu_count() - 2) as pool:
        pool.map(process_a_spec, mp_args)


if __name__ == "__main__":
    args = parser.parse_args()
    time_specs = parse_time_spec(args.input_timefile)
    kind_files = parse_kind_spec(args.kind_file)
    specs = group_specs(time_specs, kind_files)
    
    process_specs(specs, args.output_file)
