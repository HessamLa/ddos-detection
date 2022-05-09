# This script will calculate timewin entropies of given series of FTDs (flowtabel data)
# %%
from logging import exception
import os, sys
import pathlib
import time
from datetime import  datetime, timedelta, timezone
import getopt
import pytz
import pandas as pd
import numpy as np
from sympy import true
from torch import TracingState

# from imp import reload
# %reload_ext autoreload
# %autoreload 2

# %%
DATASET_NAME="cicddos2019"

HOMEDIR = os.path.expanduser("~")
DDOSDIR = f"{HOMEDIR}/ddos-detection"
SRCDIR=f"{DDOSDIR}/src"

DATASETDIR = f"{DDOSDIR}/datasets/{DATASET_NAME}"
FTDDIR=f"{DATASETDIR}/ftd-t5"
PCAPDIR=f"{DATASETDIR}/pcap"
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
import argparse
parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--pattern', '-p', type=str,   default="SAT-01-12", help='filename pattern')
parser.add_argument('--twin',    '-t', type=float, default=10.0, help='time window')
parser.add_argument('--cmethod', '-m', type=str,   default='catlog2', help='categorization method. catlog2, catlog10, catloge')
parser.add_argument('--cfield',  '-f', type=str,   default='pktcnt', help='categorization field. pktcnt, pktlen')
args = parser.parse_args()

if(args.cmethod=="none"):
  args.cfield="any"


# %%
PATTERNS_GROUP=["SAT-01-12", "SAT-03-11"] # filename patterns
CMETHOD_GROUP=['none', 'catlog2', 'catlog10', 'catloge']
CFIELD_GROUP=['any', 'pktcnt', 'pktlen', 'avglen']
  
# FILENAME_PATTERN = "SAT-03-11" #day 2
# FILENAME_PATTERN = "SAT-01-12" #day 1
FILENAME_PATTERN = PATTERNS_GROUP[0] # Default pattern setting
TIME_WINDOW = 10               # Default timewindow

# get the input from user
FILENAME_PATTERN = args.pattern
TIME_WINDOW = args.twin
CMETHOD = args.cmethod
CFIELD = args.cfield

# MAX_CID must be determined by cat-method and time-win. Also each dataset 
# has different variation, which must be taken into account
MAX_CID = 13 

if(FILENAME_PATTERN not in PATTERNS_GROUP):
  eprint("ERR ", FILENAME_PATTERN, "unknown")
  raise Exception("Unknown filename pattern")
if(CMETHOD not in CMETHOD_GROUP):
  eprint("ERR ", CMETHOD, "unknown")
  raise Exception("Unknown categorization method")
if(CFIELD not in CFIELD_GROUP):
  eprint("ERR ", CFIELD, "unknown")
  raise Exception("Unknown categorization field")

if (CMETHOD == "none"): # only one category
  CID_GROUP = [0] # group of category IDs for this method
else:
  CID_GROUP = [i+1 for i in range(MAX_CID)]

print(f"filename pattern:{FILENAME_PATTERN}, time window:{TIME_WINDOW}, cmethod:{CMETHOD}, cfield:{CFIELD}")
# files = [f"{ftddir}/{f}" for f in os.listdir (ftddir) if "SAT-01-12" in f]
files = [f"{FTDDIR}/{f}" for f in os.listdir (FTDDIR) if FILENAME_PATTERN in f]
files.sort()
for f in files[:3]:
  print(f)

# %%
ENTROPIES_DEST_DIR = f"./categories-tovictim-{FILENAME_PATTERN}/{CMETHOD}/{CFIELD}/t{TIME_WINDOW:02.0f}"

pathlib.Path(ENTROPIES_DEST_DIR).mkdir(parents=True, exist_ok=True)

# %%

victim_addrs=["192.168.50.1", "192.168.50.4", "205.174.165.81", "192.168.50.8", "192.168.50.5", 
              "192.168.50.6", "192.168.50.7", "192.168.50.9", "192.168.50.6", "192.168.50.7", "192.168.50.8"]

# %%
# cicddos2019 timestamps
# tstimes={}
# # The times are given on Toronto time. But PCAP timestamps are Unix GMT. Therefore, we need to add 4 to hour
# tz_atlantic=pytz.timezone('Canada/Atlantic')
# gmtadjust = 0
# tstimes["NTP"]      = (datetime(2018, 11, 3, 10+gmtadjust, 35, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 10+gmtadjust, 45, tzinfo=tz).timestamp())
# tstimes["DNS"]      = (datetime(2018, 11, 3, 10+gmtadjust, 52, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 11+gmtadjust,  5, tzinfo=tz).timestamp())
# tstimes["LDAP"]     = (datetime(2018, 11, 3, 11+gmtadjust, 22, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 11+gmtadjust, 32, tzinfo=tz).timestamp())
# tstimes["MSSQL"]    = (datetime(2018, 11, 3, 11+gmtadjust, 36, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 11+gmtadjust, 45, tzinfo=tz).timestamp())
# tstimes["NetBIOS"]  = (datetime(2018, 11, 3, 11+gmtadjust, 50, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 12+gmtadjust, 00, tzinfo=tz).timestamp())
# tstimes["SNMP"]     = (datetime(2018, 11, 3, 12+gmtadjust, 12, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 12+gmtadjust, 23, tzinfo=tz).timestamp())
# tstimes["SSDP"]     = (datetime(2018, 11, 3, 12+gmtadjust, 27, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 12+gmtadjust, 37, tzinfo=tz).timestamp())
# tstimes["UDP"]      = (datetime(2018, 11, 3, 12+gmtadjust, 45, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 13+gmtadjust,  9, tzinfo=tz).timestamp())
# tstimes["UDP_Lag"]  = (datetime(2018, 11, 3, 13+gmtadjust, 11, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 13+gmtadjust, 15, tzinfo=tz).timestamp())
# tstimes["WebDDoS"]  = (datetime(2018, 11, 3, 13+gmtadjust, 18, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 13+gmtadjust, 29, tzinfo=tz).timestamp())
# tstimes["SYN"]      = (datetime(2018, 11, 3, 13+gmtadjust, 29, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 13+gmtadjust, 34, tzinfo=tz).timestamp())
# tstimes["TFTP"]     = (datetime(2018, 11, 3, 13+gmtadjust, 35, tzinfo=tz).timestamp(), datetime(2018, 11, 3, 17+gmtadjust, 15, tzinfo=tz).timestamp())
# tstimes["PortMap"]  = (datetime(2018, 12, 1,  9+gmtadjust, 43, tzinfo=tz).timestamp(), datetime(2018, 12, 1,  9+gmtadjust, 51, tzinfo=tz).timestamp())
# tstimes["NetBIOS"]  = (datetime(2018, 12, 1, 10+gmtadjust, 00, tzinfo=tz).timestamp(), datetime(2018, 12, 1, 10+gmtadjust,  9, tzinfo=tz).timestamp())
# tstimes["LDAP"]     = (datetime(2018, 12, 1, 10+gmtadjust, 21, tzinfo=tz).timestamp(), datetime(2018, 12, 1, 10+gmtadjust, 30, tzinfo=tz).timestamp())
# tstimes["MSSQL"]    = (datetime(2018, 12, 1, 10+gmtadjust, 33, tzinfo=tz).timestamp(), datetime(2018, 12, 1, 10+gmtadjust, 42, tzinfo=tz).timestamp())
# tstimes["UDP"]      = (datetime(2018, 12, 1, 10+gmtadjust, 53, tzinfo=tz).timestamp(), datetime(2018, 12, 1, 11+gmtadjust,  3, tzinfo=tz).timestamp())
# tstimes["UDP_Lag"]  = (datetime(2018, 12, 1, 11+gmtadjust, 14, tzinfo=tz).timestamp(), datetime(2018, 12, 1, 11+gmtadjust, 24, tzinfo=tz).timestamp())
# tstimes["SYN"]      = (datetime(2018, 12, 1, 11+gmtadjust, 28, tzinfo=tz).timestamp(), datetime(2018, 12, 1, 17+gmtadjust, 35, tzinfo=tz).timestamp())

# tslabels is an orderd list of tuples. Each tuple is (timestamp, label). any ts<timestamp corresponds to label
# times of this dataset is reported according to Atlantic Standard Time
get_ts = lambda dt: pytz.timezone('Canada/Atlantic').localize(dt).timestamp()
TSLABELS=[
          (get_ts(datetime(2018, 12, 1, 10, 35)), "NORMAL"),
          (get_ts(datetime(2018, 12, 1, 10, 45)), "NTP"),
          (get_ts(datetime(2018, 12, 1, 10, 52)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 11,  5)), "DNS"), 
          (get_ts(datetime(2018, 12, 1, 11, 22)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 11, 32)), "LDAP"), 
          (get_ts(datetime(2018, 12, 1, 11, 36)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 11, 45)), "MSSQL"), 
          (get_ts(datetime(2018, 12, 1, 11, 50)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 12, 00)), "NetBIOS"), 
          (get_ts(datetime(2018, 12, 1, 12, 12)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 12, 23)), "SNMP"), 
          (get_ts(datetime(2018, 12, 1, 12, 27)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 12, 37)), "SSDP"), 
          (get_ts(datetime(2018, 12, 1, 12, 45)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 13,  9)), "UDP"), 
          (get_ts(datetime(2018, 12, 1, 13, 11)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 13, 15)), "UDP_Lag"), 
          (get_ts(datetime(2018, 12, 1, 13, 18)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 13, 29)), "WebDDoS"), 
          (get_ts(datetime(2018, 12, 1, 13, 29)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 13, 34)), "SYN"), 
          (get_ts(datetime(2018, 12, 1, 13, 35)), "NORMAL"), 
          (get_ts(datetime(2018, 12, 1, 17, 15)), "TFTP"), 
          (get_ts(datetime(2018, 12, 1, 23, 59)), "NORMAL"), 
          
          (get_ts(datetime(2018, 11, 3,  9, 43)), "NORMAL"), 
          (get_ts(datetime(2018, 11, 3,  9, 51)), "PortMap"), 
          (get_ts(datetime(2018, 11, 3, 10,  0)), "NORMAL"), 
          (get_ts(datetime(2018, 11, 3, 10,  9)), "NetBIOS"), 
          (get_ts(datetime(2018, 11, 3, 10, 21)), "NORMAL"), 
          (get_ts(datetime(2018, 11, 3, 10, 30)), "LDAP"), 
          (get_ts(datetime(2018, 11, 3, 10, 33)), "NORMAL"), 
          (get_ts(datetime(2018, 11, 3, 10, 42)), "MSSQL"), 
          (get_ts(datetime(2018, 11, 3, 10, 53)), "NORMAL"), 
          (get_ts(datetime(2018, 11, 3, 11,  3)), "UDP"), 
          (get_ts(datetime(2018, 11, 3, 11, 14)), "NORMAL"), 
          (get_ts(datetime(2018, 11, 3, 11, 24)), "UDP_Lag"), 
          (get_ts(datetime(2018, 11, 3, 11, 28)), "NORMAL"), 
          (get_ts(datetime(2018, 11, 3, 17, 35)), "SYN"),
          (get_ts(datetime(2018, 11, 3, 23, 59)), "NORMAL")
]

# %%
# output ts labels
for i in range(len(TSLABELS)):
  ts, label = TSLABELS[i]
  print(f"{i:2d}  {ts}  {datetime.fromtimestamp(ts)}  {label}")

# %%
# given a timestamp, gets the label from TSLABELS
def get_label(ts):
  TSidx = 0
  while(TSLABELS[TSidx][0] < ts_to):
    # print(TSLABELS[TSidx][0], ts_to)
    if(TSidx < len(TSLABELS) -1):
      TSidx += 1
  
  # print(ts_to, TSLABELS[TSidx][0], TSidx, TSLABELS[TSidx][1])
  label = TSLABELS[TSidx][1]
  return label

def ts2str(ts):
  # return f"{datetime.fromtimestamp(ts).strftime('%y-%m-%d-%H:%M:%S')}"
  return f"{datetime.fromtimestamp(ts)}"

# %%


def filter_to_victim(df):
  df = df[df['saddr'].apply(lambda x: str(x) not in victim_addrs)]
  return df

filter_dataframe=filter_to_victim
# %%
stat_columns = ["flowcnt", "pktcnt", "avglen", "pktmean", "pktstd"] # pktmean: pktcnt mean per flow, pktstd: pktcnt std per flow
entropy_columns = ["saddr", "daddr", "proto", "sport", "dport"]

category_methods = ("catloge", "catlog2", "catlog10")   # categorization methods
category_field = ("pktcnt", "pktlen", "avglen")         # fields on which categorization methods will be applied
def categorize_dataframe(dfcol, catmethod):
  """dfcol is a dataframe column, catmethod is from category_methods
  This function will return a new array, the size of dfcol, that has
  category ID for each corresponding entry in dfcol"""
  m = dfcol
  if(catmethod == "catloge"):
    cat = np.log(m, out=np.ones(m.shape)*-1, where=(m!=0)).astype(int)+1
  elif(catmethod == "catlog2"):
    cat = np.log2(m, out=np.ones(m.shape)*-1, where=(m!=0)).astype(int)+1
  elif(catmethod == "catlog10"):
    cat = np.log10(m, out=np.ones(m.shape)*-1, where=(m!=0)).astype(int)+1
  else:
    eprint("No known category method.")
    raise
  return cat
    

def flowtable_stats(df):
  """ft is a Pandas dataframe. It must have columns 'pktcnt' and 'pktlen'.
  The function returns a dictionary of statistics (sum, mean, std) and count
  of the two columns as follows
  """
  stats={}
  if(len(df) == 0):
    stats['flowcnt']      = 0
    stats['pktcnt']       = 0
    stats['meanpktcnt']   = 0
    stats['stdpktcnt']    = 0
    stats['meanpktlen']   = 0
    stats['stdpktlen']    = 0
  else:
    stats['flowcnt']      = len(df)
    stats['pktcnt']       = df['pktcnt'].sum()
    stats['meanpktcnt']   = df['pktcnt'].mean()
    stats['stdpktcnt']    = df['pktcnt'].std()
    stats['meanpktlen']   = df['pktlen'].mean()
    stats['stdpktlen']    = df['pktlen'].std()
  return stats

# %%



data={cid:[] for cid in CID_GROUP} # make a dictionary of CIDs

# we want the windows to be 10 seconds long. Therefore, we collect dfs and merge when the maximum time distance is this long
merger_group = []


for obj in pickle_objects(files):
    merger_group.append(obj)
    if(merger_group[-1]['ts_to'] - merger_group[0]['ts_from'] <TIME_WINDOW): # if time window is not met yet, the go to next
      continue 
    
    ts_from = merger_group[0]['ts_from'] 
    ts_to = merger_group[-1]['ts_to']
    ftds = []
    for obj in merger_group:
      ftds.append(obj['FlowTable'])
    
    merger_group =merger_group[1:] # drop the first one, FIFO for shifting
    
    ftd = FlowTable(name = "merged-ftd")
    for f in ftds:
      ftd.merge_ftd(f)    
    
    df = ftd.to_df()
    df = filter_dataframe(df)

    # Since IPv4 and IPv6 are incomparable, we need to convert them to strings
    df.saddr = df.saddr.apply(str)
    df.daddr = df.daddr.apply(str)
    
    # Now calculate categorical label of each flow
    df['avglen'] = df['pktlen']/df['pktcnt']

    # make the reports
    print(
      f"{ts2str(ts_from)} , {ts2str(ts_to)}, {get_label(ts_to):10s}",
      f"flows:{len(df):8d}, meanpkts:{df['pktcnt'].mean():8.2f}, stdpkts:{df['pktcnt'].std():8.2f}")
    
    if(CMETHOD == "none"):
      ts = {'ts-from':ts_from, 'ts-to':ts_to}
      stats = flowtable_stats(df)
      ents = dataframe_entropies(df, columns=entropy_columns)
      d = {}
      d = ts | stats | ents # merge all dictionaries    
      d['label'] = get_label(ts_to)
      
      cid = 0 # becaus this is "none" method
      data[cid].append(d)
    else:
        # make this parallel
        cmt = f'{CMETHOD}-{CFIELD}'
        # add a new colum for category id
        df[cmt] = categorize_dataframe(df[CFIELD], CMETHOD)
        for cid in CID_GROUP:
          tempdf = df[df[cmt] == cid]
          ts = {'ts-from':ts_from, 'ts-to':ts_to}
          stats = flowtable_stats(tempdf)
          ents = dataframe_entropies(tempdf, columns=entropy_columns)
          d = ts | stats | ents # merge all dictionaries
          d['label'] = get_label(ts_to)
          data[cid].append(d)
    
    if(ts_to%300 == 0): # for every 300 seconds
      for cid in CID_GROUP:
        output_pickle = f"{ENTROPIES_DEST_DIR}/cid{cid:02d}.pkl"
        writer = pickle_write(output_pickle)
        writer.dump(data[cid])
        writer.close()
for cid in CID_GROUP:
  output_pickle = f"{ENTROPIES_DEST_DIR}/cid{cid:02d}.pkl"
  writer = pickle_write(output_pickle)
  writer.dump(data[cid])
  writer.close()

# edf = pd.DataFrame(entropies)
# # edf.to_csv(f'df-entropies-{filename_pattern}-t{TIME_WINDOW:02d}.csv',index_label=False)
# edf.to_pickle(f'df-entropies-t{TIME_WINDOW:02d}-{FILENAME_PATTERN}.df')

tprint("Done")
exit()

# %%
