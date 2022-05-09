#!/usr/bin/env python3
# %%
import sys, os
import pandas as pd
import numpy as np

import matplotlib.pyplot as plt
# %%
HOMEDIR = os.path.expanduser("~")
DDOSDIR = f"{HOMEDIR}/ddos-detection"
SRCDIR=f"{DDOSDIR}/src"

paths=[SRCDIR]
for path in paths:
  if (path not in sys.path):
    sys.path.append(path)

# %reload_ext autoreload
# %autoreload 2
# import src

import utilities as util

# import importlib
# import datastructures.flowTable
# import streamer

import utilities as util
# from utilities import entropy, dataframe_entropies
from utilities import eprint, tprint
from utilities import pickle_write, pickle_read, pickle_objects
from datastructures.flowTable import FlowTable



import argparse
parser = argparse.ArgumentParser(description='Process some integers.')
# parser.add_argument('--pattern', '-p', type=str,   default="SAT-03-11", help='filename pattern')
parser.add_argument('--pattern', '-p', type=str,   default="SAT-01-12", help='filename pattern')
parser.add_argument('--twin',    '-t', type=float, default=10.0, help='time window')
parser.add_argument('--cmethod', '-m', type=str,   default='catlog10', help='categorization method. catlog2, catlog10, catloge')
parser.add_argument('--cfield',  '-f', type=str,   default='pktcnt', help='categorization field. pktcnt, pktlen')
# args = parser.parse_args()
args, unknown = parser.parse_known_args()

if(args.cmethod=="none"):
  args.cfield="any"

# %%
PATTERNS_GROUP=["SAT-01-12", "SAT-03-11"] # filename patterns
CMETHOD_GROUP=['none', 'catlog2', 'catlog10', 'catloge']
CFIELD_GROUP=['any', 'pktcnt', 'pktlen', 'avglen']

TIME_WINDOW = 10
FILENAME_PATTERN = "SAT-01-12"
FILENAME_PATTERN = "SAT-03-11"

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
print(f"filename pattern:{FILENAME_PATTERN}, time window:{TIME_WINDOW}, cmethod:{CMETHOD}, cfield:{CFIELD}")

if (CMETHOD == "none"): # only one category
  CID_GROUP = [0] # group of category IDs for this method
else:
  CID_GROUP = [i+1 for i in range(MAX_CID)]

ENTROPIES_DIR = f"./categories-tovictim-{FILENAME_PATTERN}/{CMETHOD}/{CFIELD}/t{TIME_WINDOW:02.0f}"
# files = [f"{ENTROPIES_DIR}/cid{cid}.pkl" for f in os.listdir (ENTROPIES_DIR) if FILENAME_PATTERN in f]
files = [f"{ENTROPIES_DIR}/cid{cid:02d}.pkl" for cid in CID_GROUP]

files.sort()
for f in files[:3]:
  print(f)


# NOTE:
# Each file is a list of dictionaries.
# Each element in the list is for a time window, and is dictionary type

def load_data(filename):
  reader = pickle_read(filename)
  data = reader.load()
  reader.close()
  return data
data={}
for cid,f in zip(CID_GROUP, files):
  data[cid] = load_data(f) 

# %%
label_categories=['NORMAL', 'DNS', 'LDAP', 'MSSQL', 'NTP', 'NetBIOS', 'SNMP', 
'SSDP', 'SYN', 'TFTP', 'UDP', 'UDP_Lag', 'WebDDoS']
label_id = {label_categories[i]:i for i  in range(len(label_categories))}

maindf={}
cids=[]
for cid, d in data.items():
  df = pd.DataFrame.from_dict(d)
  print(df.iloc[0]['label'], 
        df.iloc[-1]['label'], 
        df.iloc[-1]['ts-to'],
        df.iloc[-1]['ts-from']
        ) 
    # df['ts-to'][-1], df['ts-from'][-1])

  df["timestamp"] = df['ts-from'].apply(pd.Timestamp, unit='s')
  df.set_index("timestamp", inplace=True)
  df.drop(columns=['ts-to','ts-from'], inplace=True)
  df.fillna(0, inplace=True)
  # convert label strings to categorical according to 'categories'
  df['label'] = pd.Categorical(df['label'], categories=label_categories)
  # then convert categorical to numericals
  df['label-id'], uniques = pd.factorize(df['label'])
  # print(set(df['label']))
  # print(set(df['label-id']))
  maindf[cid] = df.copy()
  cids.append(cid)
  
# %%
print(maindf[2].head())
print(maindf[2].columns)
# %%
# for annotation, find starting and ending of each label:
# starting positions (label, starting-timestamp, starting-iloc)
# ending positions   (label, ending-timestamp,   ending-iloc)
# find starting and ending position of each label
df = maindf[cids[0]] # get the first df
# %%

i=0
label_str = [df.iloc[i]['label']]
iloc = [i]
indices = [df.index[i]]
for i in range(len(df)):
  if(label_str[-1] == df.iloc[i]['label']):
    continue
  label_str.append(df.iloc[i]['label'])
  iloc.append(i)
  indices.append(df.index[i])

Z = zip(indices.copy(), iloc.copy(), label_str.copy())
print(type(Z))
# for idx, i, l in Z:
#   print(f"{idx} {i:5d} {l}")

# %% 
print(len(maindf))

# %%
def plot_verticals(ax, indices, texts=None, **kwargs):  
  for i in range(len(indices)):
    idx = indices[i]
    ax.axvline(x=idx, **kwargs)
    s=None
    if(texts):
      s = texts[i]
      ax.text(x=idx, y=0, verticalalignment='center', s=s, fontsize='small', rotation='vertical')
    

def generate_charts(df, cols, axs, vertical_indices=None, label_str=None, show=True, save=None):
  for i in range(len(cols)):
    c = cols[i]
    ax = axs[i]
    ax.set_title(label=c, loc='left', pad=-10)
    # ax.set_ylabel(c, rotation=0)
    df[c].plot(ax=ax)
    if(vertical_indices):
      plot_verticals(ax, vertical_indices, c='r', linewidth=1)
  
  if(label_str):
    (df['label-id']*0).plot(ax=axs[-1]) # multiply by zero to make a flat line
    plot_verticals(axs[-1], indices, texts=label_str, c='r', linewidth=1)

cols = ['flowcnt', 'pktcnt', 'meanpktcnt', 'stdpktcnt', 'meanpktlen', 'stdpktlen',
       'entropy-saddr', 'entropy-daddr', 'entropy-proto', 'entropy-sport', 'entropy-dport',
       'normalized-saddr', 'normalized-daddr', 'normalized-proto', 'normalized-sport', 'normalized-dport']
print("CID_CROUP:", CID_GROUP)
for cid in CID_GROUP:
  print("cid:", cid)
  fig, axs = plt.subplots(nrows=len(cols)+1, sharex=True, figsize=(20,16),
          gridspec_kw={'height_ratios': [1]*len(cols)+[2]})
  df = maindf[cid]
  generate_charts(df, cols, axs, vertical_indices=indices, label_str=label_str)
  fig.suptitle(f"{ENTROPIES_DIR} cid:{cid}", fontsize=16)
  savepath = f"images/{CMETHOD}-t{TIME_WINDOW}-cid{cid:02d}.png"
  fig.savefig(savepath)
  print(f"saved to {savepath}")
  fig.show()
# %%
# draw stack of entropies, weighted by packet count, normalized to sum 1

# %%
cid=7
df = maindf[cid]

cols = ['flowcnt', 'pktcnt', 'meanpktcnt', 'stdpktcnt', 'meanpktlen',
       'stdpktlen',
       'entropy-saddr', 'entropy-daddr', 'entropy-proto', 'entropy-sport', 'entropy-dport',
       'normalized-saddr', 'normalized-daddr', 'normalized-proto', 'normalized-sport', 'normalized-dport']

fig, axs = plt.subplots(nrows=len(cols)+1, sharex=True, figsize=(20,16),
        gridspec_kw={'height_ratios': [1]*len(cols)+[2]})
for i in range(len(cols)):
  c = cols[i]
  ax = axs[i]
  ax.set_title(label=c, loc='left', pad=-1)
  df[c].plot(ax=ax)
  plot_verticals(ax, indices, c='r', linewidth=1)

(df['label-id']*0).plot(ax=axs[-1]) # multiply by zero to make a flat line
plot_verticals(axs[-1], indices, texts=label_str, c='r', linewidth=1)

fig.suptitle(f"{ENTROPIES_DIR} cid:{cid}", fontsize=16)
fig.savefig(f"img-t{TIME_WINDOW}-cid{cid:02d}.png")
fig.show()
#%%
x = df['label-id']
fig, ax = plt.subplots(1,1)
ax.plot(x)
print(x.head())
for idx in index:
  ax.axvline(x=idx, c='r')
# %%
print(df['label-id'])
df['label-id'].plot()
print(len(cols))
print(len(axs))
# %%
cid=3
for cid, df in maindf.items():
  print(set(df['label-id']))

# %%
# %%





tags = [(df.index[0], df.iloc[0]['label'])] # tuples
t1,t2 = tags[0]
print(tags[0])
plt.axvline(t1)
for i in range(1, len(df)):
  if(t2 != df.iloc[i]['label']):
    t1 = df.index[i]
    t2 = df.iloc[i]['label']
    tags.append((t1,t2))
    print(tags[-1])
    
    plt.axvline(t1, color='r')
# %%
print(df.index[0])
print(df.index[-1])
print(df.iloc[0].label)
# print(df.head())


# %%
# show
cid=4
df = maindf[cid].copy()

# print("duration", max(df.timestamp)-min(df.timestamp))
print(df.columns)
axs=df.plot(subplots=True, figsize=(30,20))
fig = axs[0].get_figure()
fig.suptitle(f"{ENTROPIES_DIR} cid:{cid}", fontsize=16)
plt.show()
fig.savefig(f"img-t{TIME_WINDOW}-cid{cid:02d}.png")
#%%
# collectd all df
cid=CID_GROUP[0]
# newdf = pd.DataFrame(maindf[cid]['label'])
newdf = maindf[cid]['label'].copy()

cols=['flowcnt', 'pktcnt', 'meanpktcnt', 'stdpktcnt', 'meanpktlen',
      'stdpktlen', 'entropy-saddr', 'entropy-daddr', 'entropy-proto',
      'entropy-sport', 'entropy-dport']
dfs=[newdf]
for cid in maindf.keys():
  df = maindf[cid].copy()
  newcolnames = {}
  for c in cols:
    newcolnames[c]=f"cid{cid}-{c}"
  df.rename(columns=newcolnames, inplace=True)
  dfs.append(df.copy())

newdf = pd.concat(dfs, axis=1)
newdf.head()
# %%
# NOW newdf is ready to be fed to a neural network
