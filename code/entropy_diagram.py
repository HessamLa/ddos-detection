#!/usr/bin/env py3
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import time

from utilities import eprint
from pcapstream import pickle_read

class EntropyDiagram:
  def __init__ (self, N, fig_title="Entropy diagram"):
    self.i = 5
    self.fig_title = fig_title
    self.image_name = "Entropy diagram"
    self.y_title = 'Entropy'
    self.colors  = ['red',       'green',          'cyan',        'black',             'magenta',   'blue',      'yellow', 'brown']
    self.labels  = ['Source IP', 'Destination IP', 'Source Port#', 'Destination Port#', 'Protocols', 'Packet Count Entropy']
    self.markers = ['x',         '+',              '.',            'D',                 's',         '^']
    
    self.pr = None # Pickle Read, for reading entropies from file    
    self.initfigure (N=N)
    return

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
    # patch_srcip  = mpatches.Patch(color=self.colors[0], hatch=self.hatches[0], label='Source IP')
    # patch_dstip  = mpatches.Patch(color=self.colors[1], hatch=self.hatches[1], label='Destination IP')
    # patch_srcprt = mpatches.Patch(color=self.colors[2], hatch=self.hatches[2], label='Source Port#')
    # patch_dstprt = mpatches.Patch(color=self.colors[3], hatch=self.hatches[3], label='Destination Port#')
    # patch_proto  = mpatches.Patch(color=self.colors[4], hatch=self.hatches[4], label='Protocols')
    # patch_pktcnt = mpatches.Patch(color=self.colors[5], hatch=self.hatches[5], label='Packet Count Entropy')
    # self.patches = [patch_srcip, patch_dstip, patch_srcprt, patch_dstprt, patch_proto, patch_pktcnt]
    
    # plt.subplots_adjust (top=0.961, bottom=0.05, left=0.053, right=0.982, hspace=0.071, wspace=0.2)
    plt.subplots_adjust (top=0.91, bottom=0.09, left=0.045, right=0.99, hspace=0.071, wspace=0.2)
    return

  def make (self, data, axno=0, entropy_set={'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto', 'PktCnt'},
            entropy_feature=0, window=4000, motion=False):
    '''- data is a list of format (id, name, entropy) = data [e]
    - axno is the index of axis to be addressed, from the list of self.axs
    - entropy_set is a set that must include at least one of the elements of the set {'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto'}
    This function makes the plot based on the required type
    - entropy_feature is an integer 0 or 1. If 0, it includes the 'count entropy'. If 1, it includes the 'length entropy'
    - window is the length of the diagram in seconds.

    The function returns the timestamp of the last object drawn. This value can be used as a return to assess how much
    the drawing procedure has proceeded in seconds.
    '''
    n = axno # Number of axis
    ef = entropy_feature # ID of the feature to be 
    ind = -1
    p = set() # for dymanic legends
    labels = []
    axes = []
    timebase = None
    for e in data:
      ind += 1
      (id, name, entropy, t, twin) = data [e]
      # print (id, '{:<12}'.format (name), t, twin)
      if (name not in entropy_set):
        continue
      if (timebase == None):
        timebase = t
      
      # print ('entropy_diagram()', id, name, entropy[ef], t, twin)
      # x = np.ones (entropy[ef].shape) * self.i
      
      a = self.axs[n].scatter (t+twin, entropy[ef],marker=self.markers[id-1], label=name,\
        facecolor=self.colors[id-1], s=8)
      axes.append(a)
      labels.append (self.labels[id-1])
    plt.legend (axes, labels)
      

    self.i += 0.25
    # self.axs[n].set_xlim ((-100+self.i,1+self.i), auto=False) # set width of the x axis
    ## FIX THIS PART ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if (motion):
      self.axs[n].set_xlim ((-window+t,1+t), auto=False) # set width of the x axis
    else:
      self.axs[n].set_xlim ((-window+t,1+t), auto=False) # set width of the x axis

    return t+twin
    # plt.pause(0.01)

  def show (self, pause=None):
    if (pause == None):
      plt.show ()
    else:
      plt.pause(pause)

    
  def savefigure (self, filename):
    dpi = 600
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

  show_image = False
  savename = 'fig'
  entropyset = {'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto', 'PktCntCtgry'}
  filepaths = []
  titles = []
  window = 0

  usage_msg = 'Usage: {} -<opt> <input-entropies.dmp>'.format (argv[0])
  usage_msg +='\n-w,--window[=<number>]    Window time for each slide to be stored. '+\
                                      'This number will be appended to the filename.'
  usage_msg +='\n-i (--show-image)           Show the output image'
  usage_msg +='\n-s,--save[=<filename>]      Saves figure to filename.'
  usage_msg +='\n-e,--entropyset[=<string>]  Set of entropies to show. It is a comma-separated.'
  usage_msg +='\n                            string including any of the following'
  usage_msg +='\n                            {\'SrcIP\', \'DstIP\', \'SrcPrt\', \'DstPrt\', \'Proto\'}'
  usage_msg +='\n-f,--inputfile[=<string>]   Set of input entropy files. It is a comma-separated.'
  usage_msg +='\n-t,--title[=<string>]       Set of input titles for each entropy figure (v-axis). It is a comma-separated.'
  usage_msg +='\n                            Number of items in this set should be equal to that of -i. If it is'
  usage_msg +='\n                            less, then missing items will be replaced by the corresponding filename.'
  try:
    opts, args = getopt.getopt(argv[1:],"his:e:w:f:t:",["help","show-image", "save","entropyset", "window", "inputfile", "title"])
  except getopt.GetoptError:
    eprint ('ERR: Problem reading arguments.')
    eprint (usage_msg)
    sys.exit(2)

  for opt, arg in opts:
    if opt in ("-h", "--help"):
      eprint (usage_msg)
      eprint ("-h (--help)           Prints this help")
      sys.exit()
    elif opt in ("-w", "--window"):
      window = float (arg)
    elif opt in ("-i", "--show-image"):
      show_image = True
    elif opt in ("-s", "--save"):
      savename = arg
    elif opt in ("-e", "--entropyset"):
      for e in arg.split (','):
        if e not in {'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto', 'PktCntCtgry'}:
          print ('ERR: \''+e+'\' is not an accepted string')
          eprint (usage_msg)
          sys.exit(2)
      entropyset = arg.split (',')
    elif opt in ("-f", "--inputfile"):
      filepaths = arg.split (',')
    elif opt in ("-t", "--title"):
      titles = arg.split (',')
    
  if (len (filepaths) > len (titles)):
    eprint ("WRN: Number of titles is less than entropy file paths")
    eprint ("Titles:", titles)
    eprint ("Repeating the last title to obtain equal number of items")
    
    i = len (titles)
    while (len(filepaths) > len(titles)):
      titles.append (filepaths [i])
      i+=1

    eprint (titles)

  return filepaths, titles, show_image, savename, entropyset, window

  # if (len (args) > 0):
  #   return filepaths, titles, savename, entropyset, window
  # else:
  #   eprint ("ERR: No entropies file is passed")
  #   return None

if __name__ == "__main__":
  import sys
  filepaths, titles, show_image, savename, ent_set, window = parse_arguments (sys.argv)

  if (filepaths == None):
    exit()
  pr = []
  for f in filepaths:
    print ("dbg", f)
    pr.append(pickle_read (f))
  i = 0
  N = len(filepaths) # number of figures, based on number of files
  data = [[] for n in range (N)]
  
  # collect all data
  for n in range (N):
    print ("dbg {} *************************".format(n))
    print ("dbg", pr[n].filepath)
    for d in pr[n].objects ():
      for e in d:
        (id, name, entropy, t, twin) = d [e]
        print ("dbg", id, '{:<12}'.format (name), twin, t, entropy)
      data[n].append (d)
      print ("dbg")
    print ("dbg*************************\n")


  L = 0 # Smalles sequence of data
  for n in range (N):
    L = max (len (data[n]), L)
  if (window == 0):
    window = L
  
  feat_name = 'length'
  fig_title = 'Length Entropy'
  ent_feat = 1 # Packet length feature
  
  feat_name = 'count'
  fig_title = 'Count Entropy'
  ent_feat = 0 # Packet count feature
  
  # ent_set = {'SrcIP', 'DstIP', 'SrcPrt', 'DstPrt', 'Proto'}
  # savename = 'fig-ent-'+feat_name+'-all'
  # fig_title += ' (ALL)'
  
  # ent_set = {'SrcIP', 'DstIP', 'PktCntCtgry'}
  # savename = 'fig-ent-'+feat_name+'-ips-timeout300'
  # fig_title += ' (IPs) idle timeout 300s'
  fig_title  += ' '+savename

  print ("savename", savename)
  print ("fig_titles", fig_title)
  # ent_set = {'SrcPrt', 'DstPrt'}
  # savename = 'fig-ent-'+feat_name+'-prt'
  # fig_title += ' (Ports)'
  
  t = 0
  timelim = window
  makenew = True
  for l in range (L):
    if (makenew):
      makenew = False
      print ("\nMake new diagram at ", t)
      img = EntropyDiagram(N, fig_title=fig_title+' w'+str(t)+'-'+str(t+window))
      
      for i in range (N):
        img.axs[i].set (ylabel=titles[i])
    
    
    for n in range (N):
      d = data[n][l]
      t = img.make (data=d, axno=n, entropy_set=ent_set, entropy_feature=ent_feat, window=window)
      # print ('{:6d} {:6d}'.format (n, t))
    
    if (t>=timelim or l==L-1):
      timelim += window
      if (show_image == True):
        img.show ()
      if (savename != None):
        # img.savefigure (savename+'-w'+str(int(t)))
        img.savefigure (savename)
      if (l<L-1):
        makenew = True


  # img.show ()
  print ("Press any key to exit")
  # input()
  





