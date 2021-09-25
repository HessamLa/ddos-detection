#!/usr/bin/env python3
import numpy as np
import os
from . import MakeDataset as md

class Prepdata: # preprocessed data
  class X: # input
    def __init__ (self):
      pass
  class Y: # labels
    def __init__ (self):
      pass

  def __init__(self, dir=None,
    col_order=[], num_classes=2, future_target=0):
    """dir is the directory that includes the data"""
    self.x = Prepdata.X()
    self.y = Prepdata.Y()
    if(dir):
      self.from_dir(dir)

    self.col_order = col_order # the column order for the input data
    self.num_classes = num_classes # number of output classes
    self.future_target = future_target
    print("New Prepdata instance created")
    print(f"  col_order size:{len(self.col_order)}")
    print(f"  num_classes:   {self.num_classes}")
    print(f"  future target: {self.future_target}")

  def to_dir(self, dir, prefix=""):
    '''Store this dataset to the directory'''
    if(dir[-1]=='/'): # remove the trailing /
      dir = dir[:-1]
    if not os.path.exists(dir):
      os.makedirs(dir)
    print(f"save to directory {dir}:")
    for k in self.x.__dict__.keys():
      a = getattr(self.x, k)
      if (type(a) is np.ndarray):
        p = f"{dir}/{prefix}x_{k}"
        np.save(p, a)
        # print(" ",p)

    for k in self.y.__dict__.keys():
      a = getattr(self.y, k)
      if (type(a) is np.ndarray):
        p = f"{dir}/{prefix}y_{k}"
        np.save(p, a)
        # print(" ",p)

  def from_dir(self, dir):
    if(dir[-1]=='/'): # remove the trailing /
      dir = dir[:-1]
    print(f"load from directory {dir}:")
    for f in os.listdir(dir):
      if(f.endswith(".npy")):
        f = f"{dir}/{f}"
        if("x_train" in f):
          self.x.train = np.load(f)
        elif("x_valid" in f):
          self.x.valid = np.load(f)
        elif("x_test" in f):
          self.x.test = np.load(f)
        elif("y_train" in f):
          self.y.train = np.load(f)
        elif("y_valid" in f):
          self.y.valid = np.load(f)
        elif("y_test" in f):
          self.y.test = np.load(f)
        else:
          continue # don't print
        # print(" ",f)

  def prepare(self, dfs, profile, data_columns=[], label_columns=[], shuffle=True, add_index=False):
    """prepares train dataset from the list of input csv files
    dfs: a list of Pandas DataFrame
    profile: an instance of the Profile class with the following required values
      profile.training.trainsize   train size
      profile.training.validsize   validatin size
      profile.training.testsize    test size
      profile.future_target        target into the future (positive)
      profile.model.input_size     input data size
    """
    p = profile # using a shorter name
    ## PREPARE DATA
    # params
    trainsize = p.training.trainsize
    validsize = p.training.validsize
    testsize = p.training.testsize

    # which columns to get?
    if (len(data_columns)==0):
      data_columns = dfs[0].columns[:-1]
    if (len(label_columns)==0): # use the last column as the label
      label_columns = dfs[0].columns[-1]
      
    x = None # [train, valid, test]
    y = None # [train, valid, test]
    n = 0
    for df in dfs:
      data = df[data_columns].values
      label = df[label_columns].values
      
      if(data.shape[0] < p.model.input_size):
        print("input data size is not enough")
        continue

      # make the sub-sequences
      # align label with data according to the input lookback length
      data_offset = p.future_target + p.future_size - 1
      label_offset = p.model.input_size + p.future_target - 1
      if (data_offset > 0):
        data = data[:-data_offset]
      if (label_offset > 0):
        label = label[label_offset:]

      xt = md.make_subsequence(data, p.model.input_size)
      yt = md.make_subsequence(label, p.future_size)
      # make indices
      it = np.array([i+n for i in range(xt.shape[0])])
      n += xt.shape[0]

      if( shuffle == True):
        # shuffle them
        xt, yt, it = md.unison_shuffled_copies(xt, yt, it)
      # make into train/valid/test datasets
      TRAIN = int(xt.shape[0]*p.training.trainsize)
      VALID = int(xt.shape[0]*p.training.validsize)+TRAIN
      xtt = [xt[:TRAIN, ...], xt[TRAIN:VALID, ...], xt[VALID:, ...]]
      ytt = [yt[:TRAIN, ...], yt[TRAIN:VALID, ...], yt[VALID:, ...]]
      itt = [it[:TRAIN, ...], it[TRAIN:VALID, ...], it[VALID:, ...]]

      # concatenate to the aggregate set
      if (x is None or y is None):
        for i in range(3):
          x = [np.array(xtt[i]) for i in range(3)]
          y = [np.array(ytt[i]) for i in range(3)]
          I = [np.array(itt[i]) for i in range(3)]
      else:
        for i in range(3):
          x[i] = np.concatenate ((x[i], xtt[i]))
          y[i] = np.concatenate ((y[i], ytt[i]))
          I[i] = np.concatenate ((I[i], itt[i]))

    if(x is not None and y is not None):
      self.x.train=x[0]
      self.x.valid=x[1]
      self.x.test =x[2]

      self.y.train=y[0]
      self.y.valid=y[1]
      self.y.test =y[2]

      self.I = Prepdata.X()
      self.I.train=I[0]
      self.I.valid=I[1]
      self.I.test =I[2]

      # one-hot for output
      # num_classes = len(set(y['train'][:, 0]))+1
      # print("Skipping tf for now")
      try:
        import tensorflow as tf
        self.y.train = tf.keras.utils.to_categorical ( self.y.train, num_classes=self.num_classes)
        self.y.valid = tf.keras.utils.to_categorical ( self.y.valid, num_classes=self.num_classes)
      except :
        pass

    # def onehot_initialization_v2(a):
    #   ncols = a.max()+1
    #   out = np.zeros( (a.size,ncols), dtype=np.uint8)
    #   out[np.arange(a.size),a.ravel()] = 1
    #   out.shape = a.shape + (ncols,)
    #   return out


if __name__ == "__main__":
  print("PrepareDataset test")
  from Profile import Profile
  p = Profile()

  p.model.input_size = 6

  # model fitting values
  p.training.EPOCHS = 2000 # number of iterations
  p.training.EVALUATION_INTERVAL = 200 # steps per epoch
  p.training.trainsize = 0.5
  p.training.validsize = 0.25
  p.training.testsize = 0.25

  p.path.root = "./"
  #!mkdir {p.path.base.replace(" ", "\ ")}
  p.path.checkpoint_path = p.path.root+"/ckpt"
  p.path.save_model_path = p.path.root+"/model"
  p.path.training_history = p.path.root+'/training_history'

  p.name = "CNN1d_dataprep"
  path_dset = f"{p.path.root}/data"
  print(path_dset)
  filenames = ["mocksmall.csv"]
  filenames = [f"../data/ds05-scen{i:02d}.csv" for i in range(1,4)]
  print(filenames)

  cols = ['humidity', 'temperature', 'dust', 'co-toxic', 'labels']
  num_classes = len([1,2,3,4,5,6,7])+1
  #make the dataset
  p.future_target = 1
  p.future_size = 1
  ds = Prepdata(col_order=cols, num_classes=num_classes, future_target=p.future_target)
  ds.prepare(filenames, p, data_columns=cols[:-1], label_columns=cols[-1])
  ds.to_dir(f"{p.path.root}/prepdata/{p.name}_{p.future_target}steps")

  print("train")
  for x,y,i in zip(ds.x.train, ds.y.train, ds.I.train):
    print(x,y,i)
  print("valid")
  for x,y,i in zip(ds.x.valid, ds.y.valid, ds.I.valid):
    print(x,y,i)
  print("test")
  for x,y,i in zip(ds.x.test, ds.y.test, ds.I.test):
    print(x,y,i)
