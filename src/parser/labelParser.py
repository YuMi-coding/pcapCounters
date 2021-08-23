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
                    records.append(record_dict)

        malicious_hosts = set()
        for rr in records:
            if rr['attack'] == 'DDoS':
                if rr['dir'] == '->':
                    attacking_source = rr['saddr']
                else:
                    attacking_source = rr['daddr']
            malicious_hosts.add(attacking_source)

        json_data = {"malicious": list(malicious_hosts)}
        with open(outputfile, "w") as outfile:
            json.dump(json_data, outfile)