import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
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
        self.ax.set(xlabel='Step', ylabel='Entropy',
            title=self.fig_title)
        self.ax.grid()
        self.ax.legend()
        self.ax.set_xlim ((-50,2), auto=False) # set width of the x axis
        self.ax.set_ylim ((-0.1,9), auto=False) # set width of the x axis
        self.handles, self.labels = self.ax.get_legend_handles_labels()
        self.fig.canvas.set_window_title (self.image_name)
        patch_srcip = mpatches.Patch(color='red', label='Source IP')
        patch_dstip = mpatches.Patch(color='cyan', label='Destination IP')
        patch_srcprt = mpatches.Patch(color='green', label='Source Port#')
        patch_dstprt = mpatches.Patch(color='black', label='Destination Port#')
        plt.legend(handles=[patch_srcip, patch_dstip, patch_srcprt, patch_dstprt])

    def draw (self, data):
        color = ['red', 'cyan', 'green', 'black', 'yellow', 'brown', 'blue', 'magenta']
        ind = 0
        
        names=[]
        entropies=[]
        for e in data:
            (id, name, entropy) = data [e]
            names.append (name)
            entropies.append (entropy[0])
            # print ('name: {:12} colors: {}'.format (name, color[ind]))
            x = np.ones (entropy[0].shape) * self.i
            self.ax.scatter (x, entropy[0],marker='.', label=name, facecolor=color[ind])
            ind += 1
        
        # x = np.ones (len(entropies)) * self.i
        # print (x, entropies)
        # self.ax.scatter (x, entropies,marker='.', label=names, facecolor=color)
            
        self.i += 2
        self.ax.set_xlim ((-50+self.i,2+self.i), auto=False) # set width of the x axis
        
        # self.ax.legend ()
        # plt.draw ()
        plt.pause(0.05)

    def savefigure (self, filename):
        plt.show()
        self.fig.savefig(filename, dpi=900)
