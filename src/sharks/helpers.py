import json
import socket

def read_config_files(filename):
    with open(filename, "r") as json_load:
        config = json.load(json_load)

    return config

def append_an_address(ll, addr):
    if not isinstance(ll, list):
        return
    try:
        socket.inet_aton(addr)
        ll.append(addr)
    except socket.error:
        pass # Not a legal address in socket
    return ll

def getAddressFilterStr(ll):
    out = ""
    for h in ll:
        if len(out) > 0:
            out += " || " # Or'ed legitimate hosts
        out += "(" + "ip.addr=="+str(h) + ")"
    return out

def getAddressPairFilterStr(ll):
    out = ""
    for h1, h2 in ll:
        if len(out) > 0:
            out += " || " # Or'ed legitimate hosts
        out += "(" + "ip.addr=="+str(h1) + "&&" + "ip.addr==" + str(h2) + ")"
    return out

def getProtocolFilterStr(ll):
    out = ""
    for h in ll:
        if len(out) > 0:
            out += " || "
        out += "(" + h + ")"
    return out

def loadProtos(config):
    return config

def loadAddresses(config):
    res = list()
    if isinstance(config, dict):
        values = config.values()
        values = list(values)
        res = list()
        for v in config.keys():
            if isinstance(v, list):
                for vv in v:
                    append_an_address(res, vv)
            else:
                append_an_address(res, v)

    if isinstance(config, list):
        for v in config:
            if isinstance(v, list):
                for vv in v:
                    append_an_address(res, vv)
            else:
                append_an_address(res, v)
    return res

def loadAddressPairs(config):
    res = list()
    if isinstance(config, dict):
        key = list(config.keys())
        for k in key:
            if not isinstance(config[k], list):
                value = list(config[k])
            else:
                value = config[k]
            for v in value:
                res.append((k,v))
    return res

