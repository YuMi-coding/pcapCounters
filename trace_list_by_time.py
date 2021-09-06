#!/usr/bin/env python3
# Get the trace list by checking their start/ending times

import dpkt # We use dpkt for stateless processing
import argparse
from datetime import datetime
from multiprocessing import Pool, Queue, cpu_count

TIME_SPEC_FORMAT ='%b %d %Y %I:%M%p'
parser = argparse.ArgumentParser(description="Read a time specify file, check a series of pcap files,\
    and output their which pcap file belongs to which file.")
parser.add_argument('-t', '--input-timefile', help='The input time specification', metavar="PATH", default="./timespec_01_12.json")
parser.add_argument('-f', '--input-folder', help='The input pcap file folder', metavar="PATH", default="../DDoS-eval/CICDDoS2019/")
parser.add_argument('-o', '--output-file', help='The output file list', default='./timespec.json')

pcap_info_queue = Queue()

def get_pcap_lists(input_folder):
    from os import listdir
    from os.path import isfile, join
    pcap_list = [join(input_folder, f) for f in listdir(input_folder) if isfile(join(input_folder, f))]
    return pcap_list

def read_a_pcap(pcap_filename):
    cap = open(pcap_filename, 'rb')
    pcap = dpkt.pcap.Reader(cap)
    start_time = 0xffffffff
    end_time = 0
    for ts, buf in pcap:
        start_time = min(ts, start_time)
        end_time = max(end_time, ts)
    pcap_info_queue.put((pcap_filename, {"start": start_time, "end": end_time}))

def read_pcaps(pcap_list):
    pcap_info = {}
    with Pool(cpu_count() - 2) as pool:
        pool.map(read_a_pcap, pcap_list)

    while pcap_info_queue.qsize():
        k, v = pcap_info_queue.get()
        pcap_info[k] = v

    return pcap_info

def insert_to_dict(dict, key, item):
    if key in dict:
        dict[key].append(item)
    else:
        dict[key] = [item]
    return dict

def matching_timeslots(times, pcaps):
    kinds_dict = {}
    for pcap in pcaps.keys():
        pcap_start = pcaps[pcap]['start']
        pcap_end = pcaps[pcap]['end']
        for kind in times.keys():
            kind_start = float(times[kind]['start'])
            kind_end = float(times[kind]['end'])

            if pcap_end < kind_end and pcap_end > kind_start:
                insert_to_dict(kinds_dict, kind, pcap)
                continue
            if pcap_start > kind_start and pcap_start < kind_end:
                insert_to_dict(kinds_dict, kind, pcap)
                continue
    return kinds_dict

def sort_kinds_dict(kinds_dict):
    for key in kinds_dict.keys():
        ll = kinds_dict[key]
        ll = sorted(ll, key=lambda x: int(x.split('_')[-1]))
        kinds_dict[key] = ll

    return kinds_dict

def write_kinds_dict(dest_filename, kinds_dict):
    import json
    with open(dest_filename, 'w') as outfile:
        json.dump(kinds_dict, outfile, indent=4)

def parse_time_spec(timespec_filename):
    import json
    json_dict = {}
    with open(timespec_filename, "r") as json_load:
        json_dict = json.load(json_load)

    time_spec = {}
    for key in json_dict.keys():
        if "start" in json_dict[key] and "end" in json_dict[key]:
            start_time = datetime.strptime(json_dict[key]["start"], TIME_SPEC_FORMAT)
            end_time = datetime.strptime(json_dict[key]["end"], TIME_SPEC_FORMAT)
            time_spec[key] = {}
            time_spec[key]["start"] = int(start_time.timestamp())
            time_spec[key]["end"] = int(end_time.timestamp())

    return time_spec

if __name__ == '__main__':
    args = parser.parse_args()
    time_specs = parse_time_spec(args.input_timefile)
    pcap_times = read_pcaps(get_pcap_lists(args.input_folder))
    kinds = sort_kinds_dict(matching_timeslots(time_specs, pcap_times))
    write_kinds_dict(args.output_file, kinds)
