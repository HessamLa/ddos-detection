#!/usr/bin/env py3
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import time

from utilities import eprint
from pcapstream import pickle_read

class StatsDiagram:
  def __init__ (self, N, fig_title="Statistics"):
    self.i = 5
    self.fig_title = fig_title
    self.image_name = "Stats"
    self.y_title = 'Count'
    self.colors = ['red', 'cyan', 'green', 'black', 'magenta', 'blue', 'yellow', 'brown']
    
    self.pr = None # Pickle Read, for reading entropies from file
    
    self.initfigure (N=N)
    
  def initfigure (self, N=1):
    plt.rc('legend', fontsize=6)
    figh = N*2+0.5
    figw = 10
    self.fig, self.axs = plt.subplots(N, figsize=(figw, figh))
    if N == 1:
      self.axs = [self.axs]

    print (self.fig_title)
    self.fig.suptitle (self.fig_title)
    i=0
    for ax in self.axs:
      # ax.set(xlabel='Step', ylabel='Entropy',
      #   title=self.fig_title+str(N))
      ax.set(ylabel=self.y_title+str(i))
      i+=1
      ax.grid()
      ax.legend()
      # ax.set_xlim ((-50,250), auto=False) # set width of the x axis
      ax.set_ylim ((-0.1,9), auto=False) # set length of the y axis
    
    for ax in self.axs[:-1]:
      ax.set_xticklabels([])

      # self.handles, self.labels = ax.get_legend_handles_labels()

    self.fig.canvas.set_window_title (self.image_name)
    patch_tf  = mpatches.Patch(color=self.colors[0], label='Total Flows')
    patch_newf  = mpatches.Patch(color=self.colors[1], label='New Flows')
    patch_1pktf = mpatches.Patch(color=self.colors[2], label='1-pkt Flows')
    patch_2pktf = mpatches.Patch(color=self.colors[3], label='2-pkt Flows')
    patch_3pktf = mpatches.Patch(color=self.colors[4], label='3-pkt Flows')
    self.patches = [patch_tf, patch_newf, patch_1pktf, patch_2pktf, patch_3pktf]
    # plt.subplots_adjust (top=0.961, bottom=0.05, left=0.053, right=0.982, hspace=0.071, wspace=0.2)
    plt.subplots_adjust (top=0.91, bottom=0.09, left=0.045, right=0.99, hspace=0.071, wspace=0.2)
    return

  def make (self, stats, axno=0, data_set={'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto'}, data_feature=0):
    '''- data is a list of format (id, name, entropy) = data [e]
    - axno is the index of axis to be addressed, from the list of self.axs
    - data_set is a set that must include at least one of the elements of the set {'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto'}
    This function makes the plot based on the required type
    - data_feature is an integer 0 or 1. If 0, it includes the 'count entropy'. If 1, it includes the 'length entropy'
    '''
    n = axno # Number of axis
    ef = data_feature # ID of the feature to be 
    ind = -1
    p = set() # for dymanic legends
    timebase = None
    for s in stats:
      ind += 1
      [
        t, twin,       # Time and timewin of this stat
        K,         # K Number of k-packet flows, k=0,1,...,K-1
        cntf, cnewf,   # Number of k-pkt flows, number of new flows
        mn_pktcnt, std_pktcnt, # Mean and std of total packet count
        mn_pktlen, std_pktlen, # Mean and std of total packet length
        mn_pktlf, std_pktlf, # Mean and std of packet length for k-pkt flows
        mn_agef, std_agef  # Mean and std of age of k-pkt flows
      ] = stats[s]
      # if (name not in data_set):
      #   continue
      if (timebase == None):
        timebase = t
      # print ('entropy_diagram()', id, name, entropy[ef], t, twin)
      # x = np.ones (entropy[ef].shape) * self.i
      
      
      self.axs[n].scatter (t+twin, entropy[ef],marker='.', label=name,\
        facecolor=self.colors[id-1], s=10)
      # plt.legend(handles=self.patches[:ind])
      p.add (self.patches[ind])
      plt.legend(handles=p)
      

    self.i += 0.25
    # self.axs[n].set_xlim ((-100+self.i,1+self.i), auto=False) # set width of the x axis
    self.axs[n].set_xlim ((-2000+t,1+t), auto=False) # set width of the x axis
    return
    # plt.pause(0.01)

  def show (self, pause=None):
    if (pause == None):
      plt.show ()
    else:
      plt.pause(pause)

    
  def savefigure (self, filename):
    dpi = 900
    print ("Saving diagram into \""+filename+"\" with DPI", dpi)
    self.fig.savefig(filename, dpi=dpi)
    print ("Done saving diagram")
    return

  def getEntropy (self, filepath):
    if (self.pr == None):
      self.pr = pickle_read (filepath)
    return self.pr.get_next ()

def parse_arguments (argv):
  import getopt

  savename = None
  entropyset = {'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto'}
  usage_msg = 'Usage: {} -<opt> <input-entropies.dmp>'.format (argv[0])
  usage_msg +='\n-s,--save[=<filename>]    Saves figure to filename'
  usage_msg +='\n-e,--entropyset[=<string>]  Set of entropies to show. It is a comma-separated'
  usage_msg +='\n              string including any of the following'
  usage_msg +='\n              {\'SrcIP\', \'DstIP\', \'SrcPrt\', \'DstPrt\', \'Proto\'}'
  try:
    opts, args = getopt.getopt(argv[1:],"hs:e:",["help","save","entropyset="])
  except getopt.GetoptError:
    eprint ('ERR: Problem reading arguments.')
    eprint (usage_msg)
    sys.exit(2)

  for opt, arg in opts:
    if opt in ("-h", "--help"):
      eprint (usage_msg)
      eprint ("-h (--help)           Prints this help")
      sys.exit()
    elif opt in ("-s", "--save"):
      savename = arg
    elif opt in ("-e", "--entropyset"):
      for e in arg.split (','):
        if e not in {'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto'}:
          print ('ERR: \''+e+'\' is not an accepted string')
          eprint (usage_msg)
          sys.exit(2)
      entropyset = arg

  if (len(args) > 0):
    return args, savename, entropyset
  else:
    eprint ("ERR: No entropies file is passed")
    return None

if __name__ == "__main__":
  import sys
  filepaths, savename, ent_set = parse_arguments (sys.argv)

  if (filepaths == None):
    exit()
  pr = []
  for f in filepaths:
    pr.append(pickle_read (f))
  i = 0
  N = len(filepaths)
  data = [[] for n in range (N)]
  
  # collect all data
  for n in range (N):
    for d in pr[n].objects ():
      data[n].append (d)

  L = 0
  for n in range (N):
    L = max (len (data[n]), L)
  
  feat_name = 'length'
  fig_title = 'Length Entropy'
  ent_feat = 0
  
  feat_name = 'count'
  fig_title = 'Count Entropy'
  ent_feat = 0
  
  savename = 'fig-entropy'

  # ent_set = {'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto'}
  # savename = 'fig-ent-'+feat_name+'-all'
  # fig_title += ' (ALL)'
  
  ent_set = {'SrcIP', 'DstIP'}
  savename = 'fig-ent-'+feat_name+'-ips-timeout300'
  fig_title += ' (IPs) idle timeout 300s'
  
  # ent_set = {'SrcPrt', 'DstPrt'}
  # savename = 'fig-ent-'+feat_name+'-prt'
  # fig_title += ' (Ports)'
  
  
  img = EntropyDiagram(N, fig_title=fig_title)
  img.axs[-1].set (ylabel='EntropyALL')
  print (L)
  for l in range (L):
    for n in range (N):
      d = data[n][l]
      img.make (data=d, axno=n, data_set=ent_set, data_feature=ent_feat)

  
  if (savename != None):
    img.savefigure (savename)
  img.show ()
  print ("Press any key to exit")
  # input()





