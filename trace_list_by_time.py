#!/usr/bin/env python3
# Get the trace list by checking their start/ending times

import argparse
from multiprocessing import Pool, Queue, cpu_count

from src.helpers import insert_to_dict
from src.trace.helpers import parse_time_spec, pcapReader, get_pcap_lists

parser = argparse.ArgumentParser(description="Read a time specify file, check a series of pcap files,\
    and output their which pcap file belongs to which file.")
parser.add_argument('-t', '--input-timefile', help='The input time specification', metavar="PATH", default="./timespec_03_11.json")
parser.add_argument('-f', '--input-folder', help='The input pcap file folder', metavar="PATH", default="../DDoS-eval/CICDDoS2019/")
parser.add_argument('-o', '--output-file', help='The output file list', default='./timespec.json')
parser.add_argument('-s', '--time-offset', help='The time difference introduced by time zone.', default='0')

pcap_info_queue = Queue()
time_offset = 0


def read_a_pcap(pcap_filename):
    pcap = pcapReader(pcap_filename)
    start_time = 0xffffffff
    end_time = 0
    for ts, buf in pcap:
        start_time = min(ts, start_time)
        end_time = max(end_time, ts)
    pcap_info_queue.put((pcap_filename, {"start": start_time + time_offset, "end": end_time + time_offset}))
    print("Finished reading:", pcap_filename, "\t, total read:", pcap_info_queue.qsize())

def read_pcaps(pcap_list):
    pcap_info = {}
    with Pool(cpu_count() - 2) as pool:
        pool.map(read_a_pcap, pcap_list)

    while not pcap_info_queue.empty():
        k, v = pcap_info_queue.get()
        pcap_info[k] = v

    return pcap_info

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
            if pcap_start < kind_start and pcap_end > kind_end:
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


if __name__ == '__main__':
    args = parser.parse_args()
    time_offset = int(args.time_offset)
    time_specs = parse_time_spec(args.input_timefile)
    pcap_times = read_pcaps(get_pcap_lists(args.input_folder))
    kinds = sort_kinds_dict(matching_timeslots(time_specs, pcap_times))
    write_kinds_dict(args.output_file, kinds)