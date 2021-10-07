import matplotlib
matplotlib.use('agg')
import matplotlib.pyplot as plt

import csv

from . import helpers

class Plotter():
    def __init__(self, data, x_legend="", y_legend=""):
        self.data = data
        self.x_legend = x_legend
        self.y_legend = y_legend
        plt.clf()

    def set_matplotlib_param(self, group, args):
        matplotlib.rc(group, **args)

    def saveFig(self, filename):
        plt.tight_layout()
        plt.savefig(filename, bbox_inches="tight")
        return self

    def saveEps(self, filename):
        # plt.set_rasterized(True)
        plt.tight_layout()
        plt.savefig(filename, format='eps',dpi=300, bbox_inches="tight")
        return self

    def saveSvg(self, filename):
        plt.tight_layout()
        plt.savefig(filename, format='svg',dpi=300, bbox_inches="tight")
        return self

    def saveMeta(self, filename):
        kind_list = list(self.data.keys())
        data = {}

        csv_filename = filename + ".csv"

        # Put all data into a dict
        for kind in kind_list:
            key = self.data[kind]["x"]
            value = self.data[kind]["y"]
            for k, v in zip(key, value):
                if k not in data:
                    data[k] = {kind: v}
                else:
                    data[k][kind] = v

        # Convert the dict into a list
        data_list = []
        for key in data.keys():
            temp_tuple = [key]
            for kind in kind_list:
                if kind not in data[key]:
                    temp_tuple.append(0)
                else:
                    temp_tuple.append(data[key][kind])
            data_list.append(tuple(temp_tuple))

        data_list = sorted(data_list, key=lambda x : x[0])

        with open(csv_filename, "w", newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            header = ["Timestamp"]
            header.extend(kind_list)
            csv_writer.writerow(header)
            for tup in data_list:
                temp = list(tup)
                csv_writer.writerow(temp)

        return self

    def addGrayBox_X(self, start_x, end_x, color='lightgray'):
        max_Y = helpers.get_max_Y(self.data)

        plt.fill_betweenx([0, max_Y],[start_x], [end_x], facecolor=color)


    def linePlot(self, data=None, alignX=False, mva = 0):
        if data is not None:
            self.data = data
        if alignX and len(self.data) > 0:
            self.data = helpers.alignX(self.data)

        for series in self.data:
            series_data = self.data[series]
            series_data["y"] = helpers.moving_average(series_data["y"], mva)
            plt.plot(series_data["x"], series_data["y"], label=series)

        plt.legend(loc="best")
        plt.xlabel(self.x_legend, fontsize=16)
        plt.ylabel(self.y_legend, fontsize=16)

        return self