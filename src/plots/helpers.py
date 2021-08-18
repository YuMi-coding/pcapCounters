def alignX(data):
    min_X = 112233445566778899
    for series in data:
        series_data = data[series]
        min_X = min(min_X, min(series_data["x"]))
    for series in data:
        series_data = data[series]
        for i, xx in enumerate(series_data["x"]):
            series_data["x"][i] = xx - min_X

    return data