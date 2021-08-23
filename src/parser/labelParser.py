import csv, json
from . import labelTypes
from . import helpers

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
        malicious_source = dict()
        legitimate_source = dict()
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

                    if int(record_dict['attack']):
                        if record_dict['category'] == 'DDoS':
                            if record_dict['dir'] == '->':
                                addr = record_dict['saddr']
                                port = record_dict['sport']
                            else:
                                addr = record_dict['daddr']
                                port = record_dict['dport']
                            if len(port) == 0 or port in helpers.EXEMPT_PORT_LIST:
                                continue
                            if addr in malicious_source:
                                malicious_source[addr].append(port)
                            else:
                                malicious_source[addr] = [port]
                        else:
                            # print(rr['category'])
                            pass
                    else:
                        if record_dict['dir'] == '->':
                                addr = record_dict['saddr']
                                port = record_dict['sport']
                        else:
                                addr = record_dict['daddr']
                                port = record_dict['dport']
                        if len(port) == 0 or port in helpers.EXEMPT_PORT_LIST:
                            continue
                        if addr in legitimate_source:
                            legitimate_source[addr].append(port)
                        else:
                            legitimate_source[addr] = [port]

        # print(malicious_source)

        # print(legitimate_source)
        legitimate_source, malicious_source = helpers.filterHosts(legitimate_source, malicious_source)

        json_data = {"malicious": malicious_source}
        with open(outputfile, "w") as outfile:
            json.dump(json_data, outfile, indent=4)