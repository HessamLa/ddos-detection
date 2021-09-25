from __future__ import absolute_import, division, print_function, unicode_literals

import numpy as np
import os
import pandas as pd

def generate_diagram (df, savetofile=None, figsize=(40,15), ylim=(-0.5,75),
                     tickspace=1800):
  import matplotlib as mpl
  import matplotlib.pyplot as plt
  # tickspace is distance between ticks in seconds
  t0 = df.index[0]
  tn = df.index[-1]
  colors=['blue','red','green','cyan','magenta','black','yellow']
  fields=['humidity', 'temperature', 'dust', 'co-toxic', 'co2', 'labels']
  
  fig1, ax1 = plt.subplots(figsize=figsize, subplot_kw={'ylim': ylim})
  for fld, col in zip(fields, colors):
    # Make a figure
    # Set up 30 minutes ticks
    tiks = np.arange(t0, tn, tickspace)
    # Draw verticals on ticks
    plt.xticks(tiks)
    df[fld].plot(ax=ax1, grid=True, color=col, legend=True)
    if (savetofile!=None):
      plt.savefig(savetofile+fld+'.png', transparent=True)
      # create a new figure for the next plot
      fig1, ax1 = plt.subplots(figsize=figsize, subplot_kw={'ylim': ylim})
  return

def multivariate_data(dataset, target, start_index, end_index, sequence_size,
                      target_size, step=1, single_step=False):
  data = []
  labels = []

  if end_index is None:
    end_index = len(dataset) - target_size

  start_index = start_index + sequence_size
  for i in range(start_index, end_index):
    indices = range(i-sequence_size, i, step)
    data.append(dataset[indices,:])
  
    if single_step:
      labels.append(target[i+target_size])
    else:
      labels.append(target[i:i+target_size])
  return np.array(data), np.array(labels)
  
def analyze_dfs(dfs, columns=None, condition_col=None, condition=None):
  """Returns mean and std of columns of the dataframe(s) based on the selected rows.

Keyword arguments:
dfs -- is one or a list of Pandas dataframes. If multiple dataframes, then
all must have the same columns
columns -- if none, all columns are chosen
To be implemented:
condition_col -- the columns to apply row selection criteria
condition -- the condition to be applied
  """
  if (type(dfs) != type([])): # if it's only one df, make it element of a list
    dfs=[dfs]
  if (columns==None):
    columns=dfs[0].columns

  tdf = pd.concat(dfs)
  i=(tdf['labels']==1)
  df_mean = tdf[columns][i].mean()
  df_std = tdf[columns][i].std() 
  return df_mean, df_std

def NormalizeData (mu, var, *args):
  # mu: numpy array
  # var: numpy array
  std = np.sqrt (var)
  t = ()
  for a in args:
    t += ((a-mu)/(std+1.0E-8),)
  if (len(args) == 1):
    return t[0]
  return t

def NormalizeDataLinear (minimum, maximum, *args):
  r = maximum-minimum
  t = ()
  for a in args:
    t += ((a-minimum)/r,)
  if (len(args) == 1):
    return t[0]
  return t

def load_dataframes (filepaths, col_order=None):
  # filepaths: an array of path strings to csv files
  # assumes column 'time' is the index
  assert type(filepaths) == list, 'filepaths must be an array of path strings'
  dfs = [] # the list of dataframes
  for path in filepaths:
    df = pd.read_csv (path, index_col='time')
    if (col_order is not None):
      df = df[col_order]
    dfs.append (df)
  return dfs

def get_stats(dfs, columns=None, filter=None):
  """
  Returns statistics (min, max, mean, std) of columns of the dataframe(s)
  based on the filtered rows. Multiple dataframes are concatenated together.

  Keyword arguments:
  dfs -- is one or a list of Pandas dataframes. If multiple dataframes, then
  all must have the same columns
  columns -- if none, all columns are chosen
  filter -- function that takes dataframe as input and filters out the dataframe
  and returns indices. Lambda functions can be passed as well.
  example:
  lambda x: (x['col_name']>0.8)
  lambda x: (x['price']>1000) & (x['type']=='4wd')
  """
  if (type(dfs) is not type([])): # if it's only one df, make it element of a list
    dfs=[dfs]
  if (columns is None): 
    columns=dfs[0].columns # use all the columns
  tdf = pd.concat(dfs)
  if (filter is None):
    i=np.ones(len(tdf.index), dtype=bool)
  else:
    i=filter(tdf)

  df_mean = tdf[columns][i].mean()
  df_std = tdf[columns][i].std() 
  df_min = tdf[columns][i].min()
  df_max = tdf[columns][i].max()
  return (df_min, df_max, df_mean, df_std)

def make_subsequence(data: np.ndarray, seq_size, offset=0, stride=1):
  """
  Parameters
  ----------
  data: numpy.ndarray
        n-dimensional input data
  seq_size: sequence size
  offset: offset
  stride: offset

  with seq_size 3, and stride 1, a (20,5) shape ndarray turns into
  a (18,3,5) shape ndarray. With stride 2 it turns into a (7,3,5)
  ndarray

  ex.
  with
    seq_size:  4
    offset:    2
    stride:    3
  data:     1234567890abcdefghijkl
  > output: [3456],[6789],[90ab],...,[hijk]
  
  with
    seq_size:  4
    offset:   -3
    stride:    5
  > output: [1234],[6789],[abcd]
  
  Returns
  -------
  x: numpy.ndarray
  """
  start = 0
  end = data.shape[0]
  if(offset > 0 and offset < end):
    start += offset
  elif (offset < 0 and -offset < end):
    end += offset
  elif offset != 0:
    print(f"The offset must be between {-end+1} and {end-1}")

  x = []
  for i in range(start, end-seq_size+1, stride):
    x.append(data[i:i+seq_size])
  return np.array(x)

def unison_shuffled_copies(*args):
  """args is a tuple of np.ndarray s"""
  if(len(args)>1):
    assert len(args[0]) == len(args[1])
  p = np.random.permutation(len(args[0]))
  ret = []
  for a in args:
    ret.append(a[p])
  return ret

if __name__=='__main__':
  p="fevac_dataset/dataset01"
  filepaths = [f'{p}/ds01-scen01.csv',
              f'{p}/ds01-scen02.csv',
              f'{p}/ds01-scen03.csv',
              f'{p}/ds01-scen04.csv', # only normal data
              f'{p}/ds01-scen05.csv', # only normal data
              f'{p}/ds01-scen06.csv', # only normal data
              f'{p}/ds01-scen07.csv'] # only normal data
  filepaths = [f'../data/data-scen0{i+1}.csv' for i in range(7)]
  
  filepaths = [filepaths[0]]
  
  print("files:")
  print(filepaths)
  sequence_size = 30
  future_target = 0 # 0 is the next immediate entry
  step = 1
  col_order=['humidity', 'temperature', 'dust', 'co-toxic', 'co2', 'labels']
  
  dfs = load_dataframes (filepaths, col_order=col_order)
  mu,var,_,_ = get_stats (dfs)
  print ("mean:\n", mu)
  print ("var:\n", var)
  
  mean = [2.05, 1.65, 11.77, 22.77, 26.86]
  var = [0.04, 0.06, 0.45, 2.44, 37.79]
  normalize = (mean, var)
  minimum = [2.05, 1.65, 11.77, 22.77, 26.86]
  maximum = [0.04, 0.06, 0.45, 2.44, 37.79]
  # normalize = True
  for df in dfs:
    
    data = df.values[:, :-1]
    label = df.values[:, -1]
    
    offset = 2
    data = data[:-offset]
    label = label[offset:]
    x = make_subsequence (data, seq_size=32)
    y = make_subsequence (label, seq_size=2)
    print(x)
  # x, y = make_subsequence (dfs,
  #   data_seq_size=sequence_size, future_target=future_target, normalize=normalize)

  
if __name__=="__main__":
  pass