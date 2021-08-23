import matplotlib
matplotlib.use('agg')

import matplotlib.pyplot as plt

from . import helpers

class Plotter():
    def __init__(self, data, x_legend="", y_legend=""):
        self.data = data
        self.x_legend = x_legend
        self.y_legend = y_legend

    def saveFig(self, filename):
        plt.savefig(filename)
        return self

    def linePlot(self, data=None, alignX=False):
        if data is not None:
            self.data = data
        if alignX and len(self.data) > 0:
            self.data = helpers.alignX(self.data)

        plt.clf()
        for series in self.data:
            series_data = self.data[series]
            plt.plot(series_data["x"], series_data["y"], label=series)

        plt.legend(loc="best")
        plt.xlabel(self.x_legend)
        plt.ylabel(self.y_legend)

        return self