import csv, json
from . import labelTypes

class LabelParser():
    def __init__(self, type):
        self.type = type
        self.functionTable = {
            labelTypes.BOT_IOT_DDOS_HTTP : self.parseBOTIOTDDOSHTTP,
        }

    def parseLabels(self, labelfile, outputfile):
        parserFunction = self.functionTable[self.type]
        parserFunction(labelfile, outputfile)

    def parseBOTIOTDDOSHTTP(self, labelfile, outputfile):
        malicious_hosts = set()
        with open(labelfile, "r") as csvfile:
            csvreader = csv.reader(csvfile, delimiter=';')
            keys = []
            records = []
            for row in csvreader:
                if len(keys) == 0:
                    for item in row:
                        keys.append(item)
                else:
                    record_dict = {}
                    for i,item in enumerate(row):
                        record_dict[keys[i]] = item

                    if record_dict['attack']:
                        if record_dict['category'] == 'DDoS':
                            if record_dict['dir'] == '->':
                                attacking_source = record_dict['saddr']
                            else:
                                attacking_source = record_dict['daddr']
                            malicious_hosts.add(attacking_source)
                        else:
                            # print(rr['category'])
                            pass

        json_data = {"malicious": sorted(list(malicious_hosts))}
        with open(outputfile, "w") as outfile:
            json.dump(json_data, outfile, indent=4)