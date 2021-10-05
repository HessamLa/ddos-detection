#!/usr/bin/env python3

# %%
from __future__ import absolute_import, division, print_function, unicode_literals
import os
import importlib
from re import VERBOSE
from types import DynamicClassAttribute
import numpy as np
import pandas as pd
import concurrent
import tensorflow as tf

class DummyClass:
  def __init__(self) -> None:
      pass
profile=DummyClass()

profile.timewin="10"

profile.model=DummyClass()
profile.model.name="CRNN_DDoS_Detection"
profile.model.historydepth=32
profile.model.input_size=160 # total 160 columns
profile.model.num_classes=2
profile.model.lstm_size = 40

profile.model.ratio_train = 0.70
profile.model.ratio_valid = 0.15
profile.model.ratio_test  = profile.model.ratio_train + profile.model.ratio_valid

timewin="10"
basedir=os.path.expanduser("~/ddos-detection")
codedir=f"{basedir}/src"
dsname="caida"
dsdir=f"{basedir}/datasets/{dsname}"
# ftddir=f"{dsdir}/ftd-t5"
dfdir=f"{dsdir}/output-t{timewin}"
dfpath=f"{dfdir}/all.df"

# %%
df = pd.read_pickle(dfpath)
# %%
df.tail()
df.srcip
#%% 
## Add labels, beyond time 1560 is attack
df["labels"]=np.array([0]*df.shape[0])
df.loc[df.time>1560, ['labels']]=1


# %%
## Make subsequences
#make subsequences
import utilities.MakeDataset as md

iterables=[['dstip', 'srcip', 'dstpt', 'srcpt', 'proto'],
            ['pktcnt', 'pktlen'],
            ['new','old'],
            ['k0', 'k1', 'k2', 'k3', 'k4']]
datacols=pd.MultiIndex.from_product(iterables)

profile.model.input_size=len(datacols)
data=[]
labels=[]
for i in range(df.shape[0] - profile.model.historydepth):
  data.append(df.iloc[i:i+profile.model.historydepth][datacols])
  labels.append(df.iloc[i+profile.model.historydepth]['labels'])

#separate data and labels and shuffle them 
import random
bag=list(zip(data,labels))
random.shuffle(bag)
data,labels=zip(*bag)

trainsize=int(len(data)*profile.model.ratio_train)
validsize=int(len(data)*profile.model.ratio_valid)
testsize=len(data)-(trainsize+validsize)

dfs_train={'data':data[:trainsize], 'labels':labels[:trainsize]}
dfs_valid={'data':data[trainsize:trainsize+validsize], 'labels':labels[trainsize:trainsize+validsize]}
dfs_test={'data':data[trainsize+validsize:],'labels':labels[trainsize+validsize:]}

# %%
## Put the data into dataset classes


ds=DummyClass()
ds.x=DummyClass()
ds.y=DummyClass()

ds.x.train=np.array([d.values for d in dfs_train['data']])
ds.y.train=np.array([d.values for d in dfs_train['labels']])
ds.y.train = tf.keras.utils.to_categorical ( ds.y.train, num_classes=profile.model.num_classes)

ds.x.valid= np.array([d.values for d in dfs_valid['data']])
ds.y.valid= np.array([d.values for d in dfs_valid['labels']])
ds.y.valid = tf.keras.utils.to_categorical ( ds.y.valid, num_classes=profile.model.num_classes)

ds.x.test= np.array([d.values for d in dfs_test['data']])
ds.y.test= np.array([d.values for d in dfs_test['labels']])


# %%
print(ds.x.valid.shape)
print(ds.y.valid.shape)

# %%

def MakeTrainData(ds, profile):
  # store the shapes into profile
  profile.model.inputshape = ds.x.train[0].shape
  profile.model.outputshape = ds.y.train[0].shape
  # no need to use one-hot for test set
  print (f"Single window of past history : {ds.x.train[0].shape}")

  # tensor slices
  profile.training.BATCH_SIZE = profile.model.input_size*8
  profile.training.BUFFER_SIZE = 100
  print("from_tensor_slices")
  train_data = tf.data.Dataset.from_tensor_slices((ds.x.train, ds.y.train))
  train_data = train_data.cache().shuffle(profile.training.BUFFER_SIZE)
  train_data = train_data.batch(profile.training.BATCH_SIZE).repeat()

  val_data = tf.data.Dataset.from_tensor_slices((ds.x.valid, ds.y.valid))
  val_data = val_data.batch(profile.training.BATCH_SIZE).repeat()
  return train_data, val_data

# make model
def MakeCRNNModel(inputshape, lstm_units, num_classes, model_name="CRNN_DDoS_Detection"):
  # make the CNN
  import tensorflow.keras.layers as kl
  layers = [
    kl.InputLayer(input_shape=inputshape),
    kl.Conv1D(filters=16, kernel_size=(5,), activation='relu', padding='same', name='conv1d16'),
    kl.MaxPool1D(4),
    kl.Conv1D(filters=32, kernel_size=(5,), activation='relu', padding='same', name='conv1d32'),
    kl.MaxPool1D(4),

    kl.Reshape((-1, 1)), # -1 is for inference
            # 10 LSTM units
    kl.LSTM(lstm_units, name="lstm1"),
    kl.Dense(32, activation='relu', name='dense1'),
    kl.Dense(32, activation='relu', name='dense2'),
    kl.Dense(32, activation='relu', name='dense3'),
    kl.Dense(num_classes, activation='softmax')
  ]
  model = tf.keras.models.Sequential(layers, name=model_name)
  lossFunction=tf.keras.losses.CategoricalCrossentropy(from_logits=False)
  # optimizerModel='sgd'
  optimizerModel=tf.keras.optimizers.Adam(1e-4)
  model.compile(loss=lossFunction, optimizer=optimizerModel,
                metrics=['accuracy'])
                # loss='mean_squared_error'
  return model

def FitModel(model, train_data,val_data, profile, verbose=False):    
  # Create a callback that saves the model's weights every 5 epochs
  cp_callback = tf.keras.callbacks.ModelCheckpoint(
      filepath=profile.path.checkpoint_path, 
      verbose=0, 
      save_weights_only=True,
      save_freq=100)

  # print(train_data.cardinality)
  # do fitting
  train_history = model.fit(train_data, epochs=profile.training.EPOCHS,
                      steps_per_epoch=profile.training.EVALUATION_INTERVAL,
                      validation_data=val_data,
                      validation_steps=50,
                      verbose=verbose, # 0 no output, 1 full output
                      callbacks=[cp_callback])

  # Save model and history
  model.save(profile.path.model) 
  with open(profile.path.training_history, 'wb') as file_pi:
    import pickle
    pickle.dump(train_history.history, file_pi)
    file_pi.close()
  
  return

profile.path=DummyClass()
profile.path.root = "."
profile.path.checkpoint_path=profile.path.root+"/model/CRNN_DDoS_Detection/checkpoint"
profile.path.prepdata = profile.path.root+"/prepdata_synth" 
profile.path.modeldata = profile.path.root+"/modeldata"
profile.path.checkpoint_path = profile.path.modeldata+"/ckpt"
profile.path.model = profile.path.modeldata+"/model"
profile.path.training_history = profile.path.modeldata+'/training_history'

profile.training=DummyClass()
profile.training.EPOCHS=100
profile.training.EVALUATION_INTERVAL=50


profile.model.inputshape = ds.x.train[0].shape
profile.model.outputshape = ds.y.train[0].shape
# no need to use one-hot for test set
print (f"Single window of past history : {ds.x.train[0].shape}")

# tensor slices
profile.training.BATCH_SIZE = profile.model.input_size*8
profile.training.BUFFER_SIZE = 256
print("from_tensor_slices")
train_data = tf.data.Dataset.from_tensor_slices((ds.x.train, ds.y.train))
train_data = train_data.cache().shuffle(profile.training.BUFFER_SIZE)
train_data = train_data.batch(profile.training.BATCH_SIZE).repeat()

val_data = tf.data.Dataset.from_tensor_slices((ds.x.valid, ds.y.valid))
val_data = val_data.batch(profile.training.BATCH_SIZE).repeat()


model = MakeCRNNModel(profile.model.inputshape, profile.model.lstm_size, profile.model.num_classes, model_name=profile.model.name)
model.summary()
print(profile.model.inputshape)
FitModel(model, train_data, val_data, profile)
# %%
