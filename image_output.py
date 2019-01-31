import matplotlib.pyplot as plt
import numpy as np

class ImageOutput:
    def __init__ (self):
        self.i = 5
        self.fig_title = "Entropy diagram"
        self.image_name = "Entropy diagram"
        self.initfigure ()
        self.points = dict ()
        
    def initfigure (self):
        plt.rc('legend', fontsize=6)
        self.fig, self.ax = plt.subplots()
        self.ax.set(xlabel='Time', ylabel='Entropy',
            title=self.fig_title)
        self.ax.grid()
        self.ax.legend()
        self.ax.set_xlim ((-0.5,50), auto=False) # set width of the x axis
        self.ax.set_ylim ((-0.5,5), auto=False) # set width of the x axis
        self.handles, self.labels = self.ax.get_legend_handles_labels()
        self.fig.canvas.set_window_title (self.image_name)

    def draw (self, data):
        color = ['red', 'blue', 'green', 'black', 'yellow']
        ind = 0
        for e in data[-1]:
            (id, name, entropy) = data [-1][e]
            # print 'name: {:12} colors: {}'.format (name, color[ind])
            x = np.ones (entropy.shape) * self.i
            self.ax.scatter (x, entropy,marker='.', label=name, facecolor=color[ind])
            ind += 1
        self.i += 1
        self.ax.legend ()
        plt.draw ()
        plt.pause(0.05)

    def savefigure (self, filename):
        plt.show()
        self.fig.savefig(filename, dpi=900)
