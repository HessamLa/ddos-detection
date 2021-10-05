#!/usr/bin/env python3
"""collects all .ent files in a given directory (entdir) and aggregates all in a
pandas dataframe. Then saves the dataframe in pickle format into the same directory"""

# %%
import os, sys, re
import pandas as pd
import importlib
import argparse

timewin="5"
if __name__=="__main__":
  if(len(sys.argv)>1):
    timewin=sys.argv[1]

basedir=os.path.expanduser("~/ddos-detection")
codedir=f"{basedir}/src"
dsname="caida"
dsdir=f"{basedir}/datasets/{dsname}"
# ftddir=f"{dsdir}/ftd-t5"
entdir=f"{dsdir}/output-t{timewin}"

from utilities import picklers
import utilities as util
from entropy_set import EntropySet

def ent2pandas(ifile:str=None, iobj:EntropySet=None, verbose=False):
  """Converts a entropy file or object to pandas dataframe
  ifile is type string, is the path to the .ent file
  iobj is type EntropySet"""
  df = pd.DataFrame()
  if (ifile != None):
    reader = util.pickle_read(ifile)
    row=dict()
    i=0
    for d in reader.objects ():
      for e in d:
        (id, name, entropy, t, twin) = d [e]
        # print ("dbg", id, '{:<12}'.format (name), twin, t, entropy)
        row['time'] = t
        row[f'cnt_{name}']=entropy[0]
        row[f'len_{name}']=entropy[1]

      
      df=df.append(row, ignore_index=True)
      i+=1
    if (verbose is True):
      print(f"from file {ifile}")
      print(f'total {i} entries')
      print(f'total {len(df.columns)} fields: {df.columns}')
  elif (iobj != None):
    raise ("ent2pandas() does not pocess EntropySet. Not implemented yet.")
    # for t in self.e_tbls:
    #             e [ self.e_tbls[t].id] = (
    #                 self.e_tbls[t].id,
    #                 self.e_tbls[t].name,
    #                 self.e_tbls[t].entropy,
    #                 STime.nowtime,
    #                 STime.timewin
    #                 )
  return df

entpaths=[f"{entdir}/{f}" for f in os.listdir(entdir) if f.endswith('.ent')]

iterables=[['dstip', 'srcip', 'dstpt', 'srcpt', 'proto'],
            ['pktcnt', 'pktlen'],
            ['new','old'],
            ['k0', 'k1', 'k2', 'k3', 'k4']]
cols=pd.MultiIndex.from_product(iterables)
df_all=pd.DataFrame(columns=cols)
for filename in entpaths:
  # get age and category based on filename
  if("entropies.ent" in filename):
    age,category=("anyage","anycategory")
    pass
  else:
    # get age of this file
    if 'new' in filename:
      age = 'new'
    elif 'prv' in filename:
      age = 'old'
    elif 'any' in filename:
      age = 'anyage'
    else:
      print(f"Unknown age in filename {filename}")
    # get category of this file
    m = re.search('-k(.+?)', filename)
    if m:
      category = m.group(0)
      category = category[1:]
    else:
      print(f"No category with file {filename}")
    
    #
  df = ent2pandas(filename)
  df_all['time']=df.time
  df_all['dstip', 'pktcnt',age,category]=df.cnt_DstIP
  df_all['srcip', 'pktcnt',age,category]=df.cnt_SrcIP
  df_all['dstpt', 'pktcnt',age,category]=df.cnt_SrcPrt
  df_all['srcpt', 'pktcnt',age,category]=df.cnt_SrcPrt
  df_all['proto', 'pktcnt',age,category]=df.cnt_Proto

  df_all['dstip', 'pktlen',age,category]=df.len_DstIP
  df_all['srcip', 'pktlen',age,category]=df.len_SrcIP
  df_all['dstpt', 'pktlen',age,category]=df.len_SrcPrt
  df_all['srcpt', 'pktlen',age,category]=df.len_SrcPrt
  df_all['proto', 'pktlen',age,category]=df.len_Proto

  print(f"{filename} age:{age} category:{category}")

# store the dataframe into a pickle
pklpath=f"{entdir}/all.df"
print(f"writing dataframe to pickle at {pklpath}")
df_all.to_pickle(f"{entdir}/all.df")
# %%
print(df_all.shape)
df_all.tail()
# %%
# df_all.srcip.pktcnt.anyage.plot()
df_all['srcip', 'pktcnt', 'anyage'].plot()
# df_all['srcip', 'pktcnt', 'anycategory'].plot() # this makes error
