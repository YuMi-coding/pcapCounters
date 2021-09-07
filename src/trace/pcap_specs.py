# The class describes a pcap's specification
import datetime


class PcapSpec():
    def __init__(self, name='UNKNOWN', files=[], timespec=None):
        self.name = name
        self.files = files
        self.timespec = timespec

    def __str__(self) -> str:
        h_equal = "="*26
        out_str = h_equal + self.name + h_equal + '\n'
        out_str += "Start time:\t" + str(datetime.datetime.fromtimestamp(self.timespec['start'])) + '\n'
        out_str += "End time:\t" + str(datetime.datetime.fromtimestamp(self.timespec['end'])) + '\n'
        out_str += "File list:\n"
        for file in self.files:
            out_str += file + '\n'
        out_str += h_equal + h_equal + "=" * len(self.name)
        return out_str

def group_specs(time_specs, kind_files):
    kindset = set()
    for kind in time_specs.keys():
        kindset.add(kind)
    for kind in kind_files.keys():
        kindset.add(kind)
    
    kindlist = list()
    for kind in list(kindset):
        if kind in time_specs.keys() and kind in kind_files.keys():
            kindlist.append(kind)

    spec_list = list()
    for kind in kindlist:
        this_spec = PcapSpec(
            name = kind,
            files = kind_files[kind],
            timespec = time_specs[kind]
        )
        spec_list.append(this_spec)

    return spec_list
