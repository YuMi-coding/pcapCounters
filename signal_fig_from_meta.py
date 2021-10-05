#!/usr/bin/env python3
# This script plots the figure from a meta csv file
import time
from datetime import datetime
import argparse
from src.meta.merge import Merger
from src.plots.plotter import Plotter

argparser = argparse.ArgumentParser(description="Reads the metadata csv files and draw a figure for it")
argparser.add_argument("-i", "--input", help="Input metadata csv.")
argparser.add_argument("-o", "--output", help="The output fig.", default="./meta_fig")
argparser.add_argument("-t", "--plot-type", choices=["per-flow"], default="per-flow", help="The kind of figure.")


def process_input(input_filename)-> Merger:
    merger = Merger()
    merger.add_a_metafile(input_filename)
    return merger

def process_plots(input_data):
    pass

def process_per_flow(input_data: Merger, output_filename):
    data, label = input_data.get_series_data()

    def _divide(op1, op2):
        if op2 == 0:
            return 0
        return op1/op2
    no_group = int(len(label)/2)

    series_name = ["Malicious signal per flow", "Total signal per flow"]
    series_data = []
    for i in range(no_group):
        id1 = {0:1,1:2}[i]
        id2 = {0:3,1:4}[i]
        series = []
        for v1, v2 in zip(data[id1], data[id2]):
            series.append(_divide(v1,v2))
        series_data.append(series)

    plot_data = {}
    for i, name in enumerate(series_name):
        plot_data[name] = {}
        plot_data[name]['x'] = data[0]
        plot_data[name]['y'] = series_data[i]

    plotter = Plotter(
        data = plot_data,
        x_legend= "Timestamp",
        y_legend= "Signal per flow"
    )
    plotter.linePlot(mva=20)
    plotter.saveFig(output_filename+".png")


if __name__ == "__main__":
    args = argparser.parse_args()

    data = process_input(args.input)

    {
        "per-flow": process_per_flow,
    }[args.plot_type](data, args.output)
