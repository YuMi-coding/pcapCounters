# The general helper functions

def insert_to_dict(dict, key, item):
    if key in dict:
        dict[key].append(item)
    else:
        dict[key] = [item]
    return dict