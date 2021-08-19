from . import helpers

class SharkConfig:
    def __init__(self, legitimate_filter="", malicious_filter=""):
        self.legitimate_filter = legitimate_filter
        self.malicious_filter = malicious_filter

class SharkConfigFactory:
    def __init__(self, extra_filter):
        self.legitimate_hosts = []
        self.malicious_hosts = []
        self.__spec_file = []
        self.extra_filter = extra_filter

    def loadSpec(self, filename):
        config = helpers.read_config_files(filename)
        if "malicious" in config:
            malicious_config = config["malicious"]
            self.malicious_hosts.extend(helpers.loadAddresses(malicious_config))
        if "legitimate" in config:
            legitimate_config = config["legitimate"]
            self.legitimate_hosts.extend(helpers.loadAddresses(legitimate_config))
        return self

    def loadMalicious(self, filename):
        config = helpers.read_config_files(filename)
        self.malicious_hosts.extend(helpers.loadAddresses(config))
        return self

    def loadLegitimate(self, filename):
        config = helpers.read_config_files(filename)
        self.legitimate_hosts.extend(helpers.loadAddresses(config))
        return self

    def __selfToFilter(self):
        legitimate_filter = str(self.extra_filter)
        malicious_filter = str(self.extra_filter)

        # Legitimate
        legitimate_str = helpers.getFilterStr(self.legitimate_hosts)
        if len(legitimate_str) > 0:
            legitimate_filter += " && (" + legitimate_str + ")"

        # Malicious
        malicious_str = helpers.getFilterStr(self.malicious_hosts)
        if len(malicious_str) > 0:
            malicious_filter += " && (" + malicious_str + ")"

        return SharkConfig(malicious_filter=malicious_filter,legitimate_filter=legitimate_filter)

    def getFilter(self, spec=None, malicious=None, legitimate=None):
        if spec is not None:
            self.loadSpec(spec)
        if malicious is not None:
            self.loadMalicious(malicious)
        if legitimate is not None:
            self.loadLegitimate(legitimate)

        return self.__selfToFilter()