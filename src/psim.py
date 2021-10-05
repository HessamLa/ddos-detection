#!/usr/bin/env python3
import getopt
import time
import numpy as np
import os
import sys
from pathlib import Path
import matplotlib.pyplot as plt
import multiprocessing as mp

import dpkt

HOMEDIR = os.path.expanduser("~")
sys.path.append(HOMEDIR)

# import locals
import utilities
import utilities as util
from utilities import eprint
from utilities import COLOR_CODE as C
from utilities.simulation_time import SimulationTime as STime

import datastructures
from datastructures.flowTable import StatsFlowTable as StatsFtbl
from datastructures.flowTable import make_categoric_ftables
from datastructures.flowTable import make_categoric_ftbl_keys 

from profiler import Profiler as P
from controller import Controller
from switch import Switch_Driver
from entropy_set import EntropySet
from entropy_diagram import EntropyDiagram



class Simulator:
  def __init__ (self, idir='.', timewin=5.0, filterstr='', filetype='pcap', protocol='',\
    show_image=False, idle_timeout=300):

    """protocol is a comma-separted list
    idle_timeout is for switch. Remove flows that are idle for longer that idle_timeout
    """

    self.timewin = float(timewin) # SImulation time window in seconds. In each window, the packets will be analyzed

    files = [f for f in os.listdir (idir) if f.endswith (filetype) and f.find (filterstr) != -1 ]    
    self.protocols = protocol
    self.show_image = show_image
    # self.ent_name = ent_name # name of the entropy to be saved as .dmp file

    self.switches = dict()
    self.controller = Controller ()
    self.entset = EntropySet()
    if(show_image):
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
    STime.initialize (basetime=basetime, simtime=0, timewin=timewin)
    print ("Base Time:", basetime)
    for sd in self.switches:
      self.switches[sd].time = basetime
    self.basetime = basetime
    # self.time = basetime

  def run(self):
    it = 0
    alldone = False
    while (not alldone):
      print (C.YLW+'Time: {:.2f} to {:.2f}\033[m'.format ( it*self.timewin, (it+1)*self.timewin))
      it += 1
      # all switches run
        
      # reset everything
      self.controller.ftbl_all.clear()
      self.entset.reinit ()
      
      # reset
      for d in self.switches:
        self.switches[d].switch.flow_table.reset ()
      t1 = time.time()
      
      # if all switches are done getting new packets, then 
      for d in self.switches:
        switch = self.switches[d]
        if switch.is_done == False:
          switch.progress ()

      t2 = time.time()
      # controller runs and collects stats from switches
      
      # get controller data and pass it to EntropySet
      # For the sake of speed, if there is only one switch, then copy it into the controller ftbl
      if (len (self.switches) == 1):
        self.controller.ftbl_all = self.switches[d].switch.flow_table.clone ("dirty")
      else:
        for d in self.switches:
          self.controller.add_ftable (self.switches[d].switch.flow_table.clone ("dirty"))
      ftbl_all = self.controller.ftbl_all
      # ftbl_all = self.controller.get_ftbl_all ()
      t3 = time.time()

      # categorize ftbl_all
      cat_method = "log2pktlen"
      cat_method = "log10pktlen"
      categories = [1, 10, 100, 1000, 10000]
      K = 6
      # cat_method = "log2pktcnt"
      # K = 13 # 0, 1, 2-3, 4-7, 8-15, 16-31, ..., 1024+
      
      cat_method = "log10pktcnt"
      categories = None
      K = 5 # 1, 2-10, 11-100, 101-1000, 1001+ 
      # # cat_method = "exppktcnt"

      print ("Make categorical ftables", cat_method, K, categories)
      cftbls = make_categoric_ftables (ftbl_all, cat_method, K=K, categories=categories)
      t_ftbl_cat = time.time () - t3
      for ftbl in cftbls:
        # print (ftbl.id, ftbl.name, STime.nowtime)
        dumpname=P.datasetname + '-t'+str(int (STime.timewin))+'-' + ftbl.name
        dumppath=P.outdir +'/'+ dumpname + '.ent'
        eset = EntropySet (ftbl=ftbl)
        eset.dumpEntropies (dumppath, mode='ab')
      
      t_entset = time.time ()-t3

      
      t0 = time.time ()
      # keys = make_categoric_ftbl_keys (ftbl_all, K=13)
      t_ftbl_keys = time.time () - t0

      # for name in keys:
      #   dumpname=P.datasetname + '-t'+str(int (STime.timewin))+'-' + name
      #   dumppath=P.outdir +'/'+ dumpname + '.ent'
      #   eset = EntropySet (ftbl=ftbl_all, entrykeys=keys[name])
      #   eset.dumpEntropies (dumppath, mode='ab')

      t_entset_keys = time.time () - t0

      # # draw the histogram
      # from histogram import get_ftbl_histogram
      # get_ftbl_histogram (ftbl_all, feat='avg_len')

      # self.entset.reinit () # remove all data in this table
      # self.entset.update (data=data)

      t4 = time.time()
      # self.entset.update (ftbl=ftbl_all)
      self.entset = EntropySet (ftbl=ftbl_all)

      self.entset.printInfo ()

      t5 = time.time()
      t_getEntropies = t5-t4
      # entropies = dict()
      # # include time
      # for id in ents.keys():
      #   id, name, e = ents [id]
      #   entropies [id] = (id, name, e, STime.nowtime, STime.timewin)

      self.entset.dumpEntropies (filename=P.entropypath, mode='ab')
      entropies = self.entset.getEntropies ()

      # convert to json
      import json
      jobj = json.dumps({'sim_info':{'nowtime':STime.nowtime, 'timewin':STime.timewin}, 'entropies':entropies})
      entropies = None
      obj=json.loads (jobj)
      print (obj['sim_info']['nowtime'], obj['sim_info']['timewin'])
      entropies = obj['entropies']

      if (self.show_image == True):
        self.entropyDiagram.make (entropies, motion=True)
        self.entropyDiagram.show (pause=0.01)
      
      def savePickle (data, attr, filename, outdir=None):
        if (not hasattr(self, attr)):
          pw = util.pickle_write (filename, mode='w+b')
          setattr(self, attr, pw)
        pw = getattr (self, attr)
        pw.dump (data)
        return

      print (C.CYN,
      'psim.run: tProgress=%.2f ftbl_all=%.2f\n'%(t2-t1, t3-t2),
      '     entset=%.2f  ftbl_cat=%.2f\n'%(t_entset, t_ftbl_cat),
      'entset_keys=%.2f ftbl_keys=%.2f\n'%(t_entset_keys, t_ftbl_keys),
      'getEntropies=%.2f'%(t_getEntropies),C.NC)

      # save entropies to file
      # savePickle (entropies, attr='entr', filename=P.entropypath)
      
      # save flow table stats to files
      for d in self.switches:
        ftbl = self.switches[d].switch.flow_table
        s = StatsFtbl.stats (ftbl, K=10)
        # StatsFtbl.print (s)
        savePickle (s, attr='stat', filename=P.statspath)
        # savePickle (s, attr='stat', filename='stat_log2'+self.switches[d].switch.name+'_t'+str(self.timewin)+'.dmp')

      # if all switches are done getting new packets, then 
      alldone = True
      for d in self.switches:
        if self.switches[d].is_done == False:
          alldone = False

      STime.advance ()
      # self.time = STime.nowtime
      sys.stdout.flush()
      # END WHILE ##########################################

    # finalize
    # raw_input ("PRESS SOME KEY TO TERMINATE")
    # print ("psim.run(): PRESS SOME KEY TO TERMINATE")
    # os.system("pause")

def parse_arguments (argv):
  # inputdir = "pcap_small"
  # inputdir = "pcap"
  # inputdir = "ds-ns3"
  # inputdir = "/home/datasets/caida/ddos-20070804"
  inputdir = "/tmp/hessamla/"
  inputtype = "pcap"

  inputdir = "~/ddos-detection/captures_netshot/"
  inputtype = "ftd" #Flow-Table Dump
  P.outdir = os.path.dirname(os.path.abspath(__file__))+'/../out'
  P.outdir = os.path.abspath(P.outdir)
  P.entropypath = P.outdir+"/entropies.dmp"
  P.statspath = P.outdir+"/stats.dmp"

  timewin = 60
  show_image = False
  
  usage_msg = 'Usage: {} -[p,f] <input-directory> -o <output-ftd-dirctory>'.format (argv[0])
  try:
    opts, args = getopt.getopt(argv[1:],"hip:f:t:o:e:s:",
                  ["help", "show-image", "pcapdir", "ftddir", "timewin", "odir",
                  "entropy-path", "stats-path"])
  except getopt.GetoptError:
    eprint ('ERR: Problem reading arguments.')
    eprint (usage_msg)
    sys.exit(2)
  for opt, arg in opts:
    if opt in ("-h", "--help"):
      eprint (usage_msg)
      eprint ("-h (--help)                Prints this help")
      eprint ("-t (--timewin) <seconds>   Width of each time window in seconds")
      eprint ("-p (--pcapdir) <pcap-dir>  Directory containing PCAP files")
      eprint ("-f (--ftddir) <ftd-dir>    Directory containing Flow-Table Dump files")
      eprint ("-o (--outdir) <out-dir>    Output directory, mainly for dump (pickle) files")
      eprint ("-e (--entropy-file) <path> Path to the output entropy dumps (pickle) file")
      eprint ("-s (--stats-file) <path>   Path to the output statistics dumps (pickle) file")
      eprint ("-i (--show-image)          Show the output image")
      sys.exit()
    elif opt in ("-i", "--show-image"):
      show_image = True
    elif opt in ("-p", "--pcapdir"):
      if (len (arg)>1):
        while (arg[-1] == '/'):
          arg = arg[:-1]

      P.datasetdir = arg
      P.datasetname = os.path.basename(arg)
      P.datsettype = "pcap"
      inputdir = arg
      inputtype = "pcap"
    elif opt in ("-f", "--ftddir"):
      if (len (arg)>1):
        while (arg[-1] == '/'):
          arg = arg[:-1]

      P.nshotdir = arg
      P.datasetname = os.path.basename(arg)
      P.datsettype = "ftd"
      inputdir = arg
      inputtype = "ftd"
    elif opt in ("-e", "--entropy-path"):
      P.entropypath = os.path.abspath(arg)
    elif opt in ("-s", "--stats-path"):
      P.statspath = os.path.abspath(arg)
    elif opt in ("-o", "--odir"):
      P.outdir = os.path.abspath(arg)
    elif opt in ("-t", "--timewin"):
      timewin = float (arg)
  if(len (args)==1):
    eprint ('WARN: No arguments are passed. Using default values.')
  
  
  eprint ('Input Directory  =', inputdir)
  eprint ('Input Type       =', inputtype)
  eprint ('Output Directory =', P.outdir)
  eprint ('Entropy path     =', P.entropypath)
  eprint ('Statistics path  =', P.statspath)
  eprint ('Time Window      =', timewin , 'seconds')
  eprint ('Show Image        ', show_image)
  eprint ('Save Entropy Dump as', P.entropypath)
  
  if (not os.path.isdir (inputdir)): 
    eprint ("ERR: Directory non existant:", inputdir)
    exit()
  for d in [P.outdir]:
    if (not os.path.isdir (d)):
      eprint ("WARN: Directory non existant:", d)
      eprint ("Creating the directory")
      os.makedirs(d)
  for f in [P.entropypath, P.statspath]:
    d = os.path.dirname(f)
    if (len (d) != 0 and not os.path.isdir (d)):
      eprint ("WARN: Directory non existant:", f)
      eprint ("Creating the directory")
      os.makedirs(d)

  return inputdir, inputtype, timewin, show_image

if __name__ == "__main__":
  from datetime import datetime
  eprint (os.getcwd())
  eprint (os.path.dirname(os.path.abspath(__file__)))
  idir, inputtype, timewin, show_image = parse_arguments (sys.argv)

  print (datetime.now(), f"started t{timewin} type:{inputtype} dir:{idir}")
  sim = Simulator (idir=idir, timewin=timewin,\
    filterstr='',\
    filetype=inputtype,\
    protocol={dpkt.ip.IP_PROTO_TCP,dpkt.ip.IP_PROTO_UDP,dpkt.ip.IP_PROTO_ICMP},\
    show_image=show_image,\
    idle_timeout=300\
    )
  sim.run()
  print (datetime.now(), f"finished t{timewin}")
  


  # print ("Enter")
  # input()
  
  
