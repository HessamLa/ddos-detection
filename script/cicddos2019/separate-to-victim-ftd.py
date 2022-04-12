# %%
import os, sys
from pathlib import Path
import time
from datetime import  datetime
import getopt

import pandas as pd
import numpy as np

DATASET_NAME="cicddos2019"
PATTERNS=["SAT-01-12", "SAT-03-11"] # filename patterns

HOMEDIR = os.path.expanduser("~")
DDOSDIR = f"{HOMEDIR}/ddos-detection"
SRCDIR=f"{DDOSDIR}/src"

DATASETDIR = f"{DDOSDIR}/datasets/{DATASET_NAME}"
FTDDIR=f"{DATASETDIR}/ftd-t5"
PCAPDIR=f"{DATASETDIR}/pcap"
FILENAME_PATTERN = "SAT-03-11" #day 2
FILENAME_PATTERN = "SAT-01-12" #day 1

paths=[SRCDIR]
for path in paths:
  if (path not in sys.path):
    sys.path.append(path)
# get_ipython().run_line_magic('load_ext', 'autoreload')
# get_ipython().run_line_magic('autoreload', '2')

# %reload_ext autoreload
# %autoreload 2
# import src

import utilities as util

# import importlib
# import datastructures.flowTable
# import streamer

import utilities as util
from utilities import entropy, dataframe_entropies
from utilities import eprint, tprint
from utilities import pickle_write, pickle_read, pickle_objects
from datastructures.flowTable import FlowTable


# %%
FILENAME_PATTERN = None
time_window = 10
if(len(sys.argv))>1:
  if(sys.argv[1] in PATTERNS):
    FILENAME_PATTERN = sys.argv[1]
  else:
    tprint(sys.argv[1], "is not acceptable")
if(len(sys.argv))>2:
  try:
    time_window = int(sys.argv[2])
  except:
    pass

if(FILENAME_PATTERN == None):
  FILENAME_PATTERN = PATTERNS[0]

tprint(f"filename pattern:{FILENAME_PATTERN}, time window:{time_window}")
# files = [f"{ftddir}/{f}" for f in os.listdir (ftddir) if "SAT-01-12" in f]
files = [f"{FTDDIR}/{f}" for f in os.listdir (FTDDIR) if FILENAME_PATTERN in f]
files.sort()
files = files[1:]
print(files[:5])
for f in files:
  print(f)

# %%
partition_size_KB=50*1024
ftdfilepath=FTDDIR=f"{DATASETDIR}/ftd-t5/to-victim"
ftdwriter = pickle_write(ftdfilepath, filepath_ext=".ftd", partition_size=partition_size_KB*1024)

victim_addrs=["192.168.50.1", "192.168.50.4", "205.174.165.81", "192.168.50.8", "192.168.50.5", 
              "192.168.50.6", "192.168.50.7", "192.168.50.9", "192.168.50.6", "192.168.50.7", "192.168.50.8"]
for obj in pickle_objects(files):
    ts_from = obj["ts_from"]
    ts_to = obj["ts_to"]
    ftd = obj["FlowTable"]
    newftd = 
    for h, e in ftd.items():
      # print(f"{e.saddr}:{e.sport} -> {e.daddr}:{e.dport} ({e.proto}) ")
      if(str(e.saddr) in victim_addrs):
        print(f"{e.saddr}:{e.sport} -> {e.daddr}:{e.dport} ({e.proto}) ")

      # else:
      #   print(f"{e.saddr}")

