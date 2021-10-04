# The meta data grouper
import csv

def insert_dict_with_kind(dict_obj, key, kind, value):
    if key not in dict_obj:
        dict_obj[key] = {}
    dict_obj[key][kind] = value
    return dict_obj


class MetaGrouper():
    def __init__(self, name = "UNKNOWN"):
        self.name = name
        self.data = {}
        self.kind_list = []

    def add_value_set(self, key, kind, value):
        self.kind_list.append(kind)
        for k, v in zip(key, value):
            insert_dict_with_kind(self.data, k, kind, v)
        return self

    # This function returns all the value in data as list of tuple,
    # and the first tuple is the header of csv
    def get_value_lists(self):
        header = ["timestamp"]
        header.extend(self.kindlist)
        result = [tuple(header)] 
        data_keys = list(self.data.keys())
        data_keys = sorted(data_keys)
        for data_key in data_keys:
            temp_tuple = [data_key]
            for kind in self.kind_list:
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
