#!/usr/bin/env python3
import getopt
import time
import numpy as np
import os
import sys
from pathlib import Path
import matplotlib.pyplot as plt
import dpkt

HOMEDIR = os.path.expanduser("~")
sys.path.append(HOMEDIR)

# import locals
from controller import Controller
from switch import Switch_Driver
from cTable import cTable
from entropy_diagram import EntropyDiagram
from flowTable import StatsFlowTable as StatsFtbl

from utilities import eprint
from utilities import COLOR_CODE as C

import multiprocessing as mp

class Simulator:
  def __init__ (self, idir='.', timewin=5.0, filterstr='', filetype='pcap', protocol='',\
    show_image=False, ent_name='ent.dmp', idle_timeout=300):

    """protocol is a comma-separted list
    idle_timeout is for switch. Remove flows that are idle for longer that idle_timeout
    """

    self.timewin = float(timewin) # SImulation time window in seconds. In each window, the packets will be analyzed
    
    files = [f for f in os.listdir (idir) if f.endswith (filetype) and f.find (filterstr) != -1 ]    
    self.protocols = protocol
    self.show_image = show_image
    self.ent_name = ent_name # name of the entropy to be saved as .dmp file

    self.switches = dict()
    self.controller = Controller ()
    self.ctable = cTable()
    self.entropyDiagram = EntropyDiagram (N=len (files))
    
    times=[]
    for f in files: # FOREACH switch-csv file, read the file and create corresponding switch obj
      # Make a switch object
      sd = Switch_Driver (f, filetype, idir, self.timewin, protocol, idle_timeout=idle_timeout)
      
      # for each switch-csv file make a switch
      self.switches [f] = sd
      times.append (float (sd.time))

      # Make one controller and introduce the switches to it
      self.controller.connect_switches ([sd.switch])
    
    # readjust time of all switches to the earliest one
    basetime = int (min (times)/timewin)*timewin
    print ("Base Time:", basetime)
    for sd in self.switches:
      self.switches[sd].time = basetime
    self.basetime = basetime
    self.time = basetime

  def run(self):
    it = 0
    alldone = False
    while (not alldone):
      print (C.YLW+'Time: {:.2f} to {:.2f}\033[m'.format ( it*self.timewin, (it+1)*self.timewin))
      it += 1
      # all switches run
        
      # clear all tables
      # for d in self.switches:
      #   self.switches[d].switch.flow_table.clear()
      self.controller.ftbl_all.clear()
      self.ctable.clear()
      
      # reset
      for d in self.switches:
        self.switches[d].switch.flow_table.reset ()
      t1 = time.time()
      
      # if all switches are done getting new packets, then 
      for d in self.switches:
        if self.switches[d].is_done == False:
          self.switches[d].progress ()

      t2 = time.time()
      # controller runs and collects stats from switches
      
      # get controller data and pass it to ctable
      # For the sake of speed, if there is only one switch, then copy it into the controller ftbl
      if (len (self.switches) == 1):
        self.controller.ftbl_all = self.switches[d].switch.flow_table_dirty
      else:
        for d in self.switches:
          self.controller.add_ftable (self.switches[d].switch.flow_table_dirty)
      ftbl_all = self.controller.ftbl_all
      # ftbl_all = self.controller.get_ftbl_all ()
      t3 = time.time()

      # self.ctable.reinit () # remove all data in this table
      # self.ctable.update (data=data)
      self.ctable.update (ftable=ftbl_all)
      t4 = time.time()

      self.ctable.printInfo ()

      ents = self.ctable.getEntropies ()
      t5 = time.time()
      entropies = dict()
      # include time
      for id in ents.keys():
        id, name, e = ents [id]
        entropies [id] = (id, name, e, self.time, self.timewin)

      if (self.show_image == True):
        self.entropyDiagram.make (entropies)
        self.entropyDiagram.show (pause=0.01)
      
      def savePickle (data, attr, filename, outdir=None):
        if (not hasattr(self, attr)):
          from pcapstream import pickle_write
          pw = pickle_write (filename, mode='w+b')
          setattr(self, attr, pw)
        pw = getattr (self, attr)
        pw.dump (data)
        return

      print ('psim.run: tProgress=%.2f ftbl_all=%.2f cTable=%.2f getEntropies=%.2f'%(t2-t1, t3-t2, t4-t3, t5-t4))

      # save entropies to file
      savePickle (entropies, attr='entr', filename=self.ent_name)
      
      # save flow table stats to files
      for d in self.switches:
        ftbl = self.switches[d].switch.flow_table
        s = StatsFtbl.stats (ftbl, K=10)
        StatsFtbl.print (s)
        savePickle (s, attr='stat', filename='stat_log2'+self.switches[d].switch.name+'_t'+str(self.timewin)+'.dmp')

      # if all switches are done getting new packets, then 
      alldone = True
      for d in self.switches:
        if self.switches[d].is_done == False:
          alldone = False

      self.time += self.timewin
      # if (self.time - self.basetime > 2595):
      #   print (C.RED+"psim.run(): ONLY FOR CAIDA DATASET THE SIM TIME IS BOUND TO 2595s"+C.NC)
      #   exit ()

      sys.stdout.flush()
      # END WHILE ##########################################

    # finalize
    # raw_input ("PRESS SOME KEY TO TERMINATE")
    print ("psim.run(): PRESS SOME KEY TO TERMINATE")
    # os.system("pause")

def parse_arguments (argv):
  # inputdir = "pcap_small"
  # inputdir = "pcap"
  # inputdir = "ds-ns3"
  # inputdir = "/home/datasets/caida/ddos-20070804"
  inputdir = "/tmp/hessamla/"
  inputtype = "pcap"
  outputdir = "/home/hessamla/ddos-detection/nshot_test/"

  inputdir = "/home/hessamla/ddos-detection/captures_netshot/"
  inputtype = "ftd" #Flow-Table Dump
  outputdir = ""
  ent_name = "ent.dmp"

  timewin = 60
  show_image = False
  
  usage_msg = 'Usage: {} -df <input-directory> -o <output-ftd-dirctory>'.format (argv[0])
  try:
    opts, args = getopt.getopt(argv[1:],"hid:f:t:o:e:",["help", "show-image", "pcapdir", "ftddir", "timewin", "odir", "entropy-name"])
  except getopt.GetoptError:
    eprint ('ERR: Problem reading arguments.')
    eprint (usage_msg)
    sys.exit(2)
  for opt, arg in opts:
    if opt in ("-h", "--help"):
      eprint (usage_msg)
      eprint ("-h (--help)            Prints this help")
      eprint ("-d (--pcapdir) <pcap-directory>  Directory containing PCAP files")
      eprint ("-f (--ftddir) <ftd-directory>  Directory containing Flow-Table Dump files")
      eprint ("-i (--show-image)        Show the output image")
      eprint ("-t (--timewin) <seconds>     Width of each time window in seconds")
      sys.exit()
    elif opt in ("-i", "--show-image"):
      show_image = True
    elif opt in ("-d", "--pcapdir"):
      inputdir = arg
      inputtype = "pcap"
    elif opt in ("-f", "--ftddir"):
      inputdir = arg
      inputtype = "ftd"
    elif opt in ("-e", "--entropy-name"):
      ent_name = arg
    elif opt in ("-o", "--odir"):
      outputdir = arg
    elif opt in ("-t", "--timewin"):
      timewin = float (arg)
  # if (len (args) > 0):
  #   inputfile = args[-1]
  else:
    eprint ('WARN: No arguments are passed. Using default values.')
  
  eprint ('Input Directory =', inputdir)
  eprint ('Input Type =', inputtype)
  eprint ('NetShot outputdir =', outputdir)
  eprint ('Time Window =', timewin , 'seconds')
  eprint ('Show Image =', show_image)
  eprint ('Save Entropy Dump as', ent_name)
  
  eprint ("")

  return inputdir, outputdir, inputtype, timewin, show_image, ent_name

if __name__ == "__main__":
  eprint (os.getcwd())
  eprint (os.path.dirname(os.path.abspath(__file__)))
  idir, outputdir, inputtype, timewin, show_image, ent_name = parse_arguments (sys.argv)

  print (idir, outputdir,inputtype, timewin)
  sim = Simulator (idir=idir, timewin=timewin,\
    filterstr='',\
    filetype=inputtype,\
    protocol={dpkt.ip.IP_PROTO_TCP,dpkt.ip.IP_PROTO_UDP,dpkt.ip.IP_PROTO_ICMP},\
    show_image=show_image,\
    ent_name=ent_name,\
    idle_timeout=300\
    )
  sim.run()
  


  # print ("Enter")
  # input()
  
  
