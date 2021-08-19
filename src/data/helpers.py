def preprocess_keys(keys, grain = 1):
    result = []
    for key in keys:
        times = int(key/grain)
        result.append(times * grain)
    return result