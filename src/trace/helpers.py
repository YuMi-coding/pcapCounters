import dpkt # We use dpkt for stateless processing
from datetime import datetime

TIME_SPEC_FORMAT ='%b %d %Y %I:%M%p'


def satisfy_timespec(ts, timespec):
    if timespec is None:
        return True
    if ('start' not in timespec) or ('end' not in timespec):
        return True
    if ts > timespec['start'] and ts < timespec['end']:
        return True
    return False

def pcapReader(pcap_filename):
    cap = open(pcap_filename, 'rb')
    return dpkt.pcap.Reader(cap)

def __load_json(filename):
    import json
    with open(filename, "r") as json_load:
        json_dict = json.load(json_load)
    return dict(json_dict)

def parse_time_spec(timespec_filename):
    json_dict = __load_json(timespec_filename)

    time_spec = {}
    for key in json_dict.keys():
        if "start" in json_dict[key] and "end" in json_dict[key]:
            start_time = datetime.strptime(json_dict[key]["start"], TIME_SPEC_FORMAT)
            end_time = datetime.strptime(json_dict[key]["end"], TIME_SPEC_FORMAT)
            time_spec[key] = {}
            time_spec[key]["start"] = int(start_time.timestamp())
            time_spec[key]["end"] = int(end_time.timestamp())

    return time_spec

def parse_kind_spec(kindspec_filename):
    json_dict = __load_json(kindspec_filename)
    return json_dict

def get_pcap_lists(input_folder):
    from os import listdir
    from os.path import isfile, join
    pcap_list = [join(input_folder, f) for f in listdir(input_folder) if isfile(join(input_folder, f))]
    return pcap_list

def write_pcap_file(dest_filename, pkts):
    writer_fd = open(dest_filename, "wb")
    writer = dpkt.pcap.Writer(writer_fd)

    written_count = 0
    for ts, buf in pkts:
        writer.writepkt(buf, ts)
        written_count += 1
        if written_count % 10000 == 0:
            written_count = 0
            writer_fd.flush()
    writer_fd.close()
