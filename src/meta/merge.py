# The metadata merger
import csv
import collections

def insert_dict_with_kind(dict_obj, key, kind, value):
    if key not in dict_obj:
        dict_obj[key] = {kind: 0}
    if kind not in dict_obj[key]:
        dict_obj[key][kind] = 0

    dict_obj[key][kind] += int(value)
    return dict_obj

class Merger():
    def __init__(self, name="unknown"):
        self.name = name
        self.data = {}
        self.header = []

    def add_a_metafile(self, meta_filename):
        input_meta = []
        with open(meta_filename, 'r', newline="") as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                input_meta.append(row)
        self.add_a_meta(input_meta)
        return self

    def add_a_meta(self, input_meta):
        header = input_meta[0]
        if len(self.header) == 0:
            self.header = header
        else:
            assert collections.Counter(self.header) == collections.Counter(header), "Mismatched header field!"

        for i, meta_data in enumerate(input_meta):
            if i == 0:
                continue
            for j, meta in enumerate(meta_data):
                if j == 0:
                    key = int(float(meta))
                else:
                    insert_dict_with_kind(self.data, key, j, meta)
            del key
        return self

    def get_value_lists(self):
        header = list(self.header)
        kind_list = header[1:]
        result = [tuple(header)]
        data_keys = list(self.data.keys())
        data_keys = sorted(data_keys)
        for data_key in data_keys:
            temp_tuple = [data_key]
            for kind in kind_list:
                if kind not in self.data[data_key]:
                    temp_tuple.append(0)
                else:
                    temp_tuple.append(self.data[data_key][kind])
            result.append(tuple(temp_tuple))
        return result

    def saveMeta(self, filename):
        data = self.get_value_lists()
        csv_filename = filename + ".csv"
        with open(csv_filename, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            for tup in data:
                temp = list(tup)
                csv_writer.writerow(temp)
        return self