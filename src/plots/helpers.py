def alignX(data):
    min_X = 112233445566778899
    for series in data:
        series_data = data[series]
        if len(series_data["x"]) > 0:
            min_X = min(min_X, min(series_data["x"]))

    for series in data:
        series_data = data[series]
        for i, xx in enumerate(series_data["x"]):
            series_data["x"][i] = xx - min_X

    return data

def moving_average(input_list, window=0):
    half_window = window / 2
    average = lambda x : sum(x)/ len(x)
    result = []
    for i in range(len(input_list)):
        start_index = int(i-half_window if i-half_window>=0 else 0)
        end_index = int(i + half_window + 1 if i + half_window + 1 < len(input_list) else len(input_list))

        result.append(average(input_list[start_index: end_index]))
    return result