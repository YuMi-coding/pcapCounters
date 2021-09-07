#!/usr/bin/env python3
# This script slices a folder of pcap traces according to the specifications

import argparse
from multiprocessing import Pool, Queue, cpu_count

from src.trace.pcap_specs import group_specs
from src.trace.helpers import parse_time_spec, parse_kind_spec


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
parser.add_argument('-s', '--time-offset', help='The time difference introduced by time zone.',
    default='0')




if __name__ == "__main__":
    args = parser.parse_args()
    time_specs = parse_time_spec(args.input_timefile)
    kind_files = parse_kind_spec(args.kind_file)
    specs = group_specs(time_specs, kind_files)
    print(specs)
