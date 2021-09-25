#!/usr/bin/env python3

"""collects all .ent files in a given directory (entdirpath) and converts each into .csv file in the same directory.
Then aggregates all .csv file into one single .csv file (df_allpath) which can be loaded using pandas dataframe"""
#%%
import pandas as pd
import os
import importlib
import argparse
# import utilities
# importlib.reload(utilities)
import utilities as util
from entropy_set import EntropySet
basepath = "/N/slate/hessamla/ddos-datasets"
entdirpath = f"{basepath}/caida/output-t10"

df_alldir=f"{basepath}/caida/output-t10-csv/df_all.csv"
df_allpath=f"{df_alldir}/output-t10-csv"

#%%
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
# %%

entpaths=[f"{entdirpath}/{f}" for f in os.listdir(entdirpath) if f.endswith('.ent')]
dfpaths=[]
dfs=dict()
if __name__=="__main__":
  parser = argparse.ArgumentParser(description="Converts .ent file or EntopySet object to Pandas dataframe and stores in a file in pickle format")
  parser.add_argument('ifile', type=str, help="path to the input .ent file")
  parser.add_argument('ofile', type=str, help="path to the input .ent file")
  for ifile in entpaths:
    ofile=ifile
    suffix=".ent"
    if ofile.endswith(suffix): # strip away .ent
      ofile=ofile[:-len(suffix)]
    ofile+="_df.gzip"
    df = ent2pandas(ifile)
    #save the dataframe to csv
    print("")
    print(f'input: {ifile}')
    print(f'output: {ofile}')
    print(f'total {df.shape[0]} entries')
    print(f'total {len(df.columns)} fields: {df.columns}')
    # df.to_csv(ofile, index=False)
    df.to_pickle(ofile)
    dfpaths.append(ofile)
    #also get file names according to their age and category


  # load into dataframes
  print("load dataframes")
  for fname in dfpaths:
    dfs[fname]=pd.read_pickle(fname)
  print("done loading")
  dfs[dfpaths[0]].head()

  agecat={
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-new-k0_df.gzip': ('new', 'k0'),
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-new-k1_df.gzip': ('new', 'k1'),
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-new-k2_df.gzip': ('new', 'k2'),
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-new-k3_df.gzip': ('new', 'k3'),
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-new-k4_df.gzip': ('new', 'k4'),
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-prv-k0_df.gzip': ('old', 'k0'),
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-prv-k1_df.gzip': ('old', 'k1'),
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-prv-k2_df.gzip': ('old', 'k2'),
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-prv-k3_df.gzip': ('old', 'k3'),
  '/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-prv-k4_df.gzip': ('old', 'k4')
  }

  # make multi-index columns for the dataframe
  iterables=[['dstip', 'srcip', 'dstpt', 'srcpt', 'proto'],
              ['flowcnt', 'pktlen', 'pktcnt'],
              ['new','old'],
              ['k0', 'k1', 'k2', 'k3']]
  cols=pd.MultiIndex.from_product(iterables)
  df_all=pd.DataFrame(columns=cols)

  df_all['time']=list(dfs.values())[0]['time']
  # df_all.set_index('time')
  for fname in agecat:
    age, cat = agecat[fname]
    print(age, cat)
    df_all['dstip', 'flowcnt',age,cat]=dfs[fname].cnt_DstIP
    df_all['srcip', 'flowcnt',age,cat]=dfs[fname].cnt_SrcIP
    df_all['dstpt', 'flowcnt',age,cat]=dfs[fname].cnt_SrcPrt
    df_all['srcpt', 'flowcnt',age,cat]=dfs[fname].cnt_SrcPrt
    df_all['proto', 'flowcnt',age,cat]=dfs[fname].cnt_Proto

    df_all['dstip', 'pktlen',age,cat]=dfs[fname].len_DstIP
    df_all['srcip', 'pktlen',age,cat]=dfs[fname].len_SrcIP
    df_all['dstpt', 'pktlen',age,cat]=dfs[fname].len_SrcPrt
    df_all['srcpt', 'pktlen',age,cat]=dfs[fname].len_SrcPrt
    df_all['proto', 'pktlen',age,cat]=dfs[fname].len_Proto
  
  if os.path.exists(df_alldir):
    import shutil
    shutil.rmtree(df_alldir)
  os.makedirs(df_alldir)
  df_all['dstip', 'flowcnt'].plot()
  df_all.to_csv(df_allpath, index=False)

  df_all['srcip', 'flowcnt'].plot()
  df_all.dstip['flowcnt'].plot()

# %%
