EXEMPT_PORT_LIST = ['80', '443']

def filterHosts(legitimate_source, malicious_source):
    filtered_malicious = {}
    filtered_legitimate = {}
    for hosts in malicious_source:
        if hosts not in legitimate_source:
            filtered_malicious[hosts] = ""
        else:
            filtered_malicious[hosts] = malicious_source[hosts]

    for hosts in legitimate_source:
        if hosts not in malicious_source:
            filtered_legitimate[hosts] = ""
        else:
            filtered_legitimate[hosts] = legitimate_source[hosts]
    return filtered_legitimate, filtered_malicious