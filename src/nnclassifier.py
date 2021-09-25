#!/usr/bin/env python3

# %%
from __future__ import absolute_import, division, print_function, unicode_literals
import os
import importlib
from types import DynamicClassAttribute
import numpy as np
import pandas as pd
import concurrent
import tensorflow as tf

import utilities as util # util.MakeDataset util.PrepareDataset

basepath = "/N/slate/hessamla/ddos-datasets"
# load data
entdirpath = f"{basepath}/caida/output-t10"
df_alldir=f"{basepath}/caida/output-t10-df"
df_allpath=f"{df_alldir}/output-t10-csv"
df_allpath=f"{df_alldir}/output-t10-df"


class DummyClass:
  def __init__(self):
    pass

#%%
df_all = [pd.read_pickle(f"{df_alldir}/{file}") for file in os.listdir(df_alldir) if file.endswith("_df.gzip")]
print(len(df_all))
print(df_all[0].head())
# %%
df_all = pd.read_csv(df_allpath, header=[0,1,2,3], skip_blank_lines=True)
df_all['srcip'].head()

# %%

df_all['srcip','flowcnt'].iloc[155:170].plot()
df_all['dstip','flowcnt'].iloc[155:170].plot()
# %%
# set labels. index 159 (1590 seconds) and onwards are attack
labels=np.array([0]*df_all.shape[0])
labels[159:]=1
df_all['labels']=labels

# %%
iterables=[['dstip', 'srcip', 'dstpt', 'srcpt', 'proto'],
            ['flowcnt', 'pktlen'],
            ['new','old'],
            ['k0', 'k1', 'k2', 'k3']]
datacols=pd.MultiIndex.from_product(iterables)

INPUT_tSIZE=32
LABEL_SIZE=1

#make subsequences
subsequences=[]
for i in range(df_all.shape[0]-INPUT_tSIZE):
  subsequences.append(df_all.iloc[i:i+INPUT_tSIZE])

#make batches of subsequences
dfs=[]
for i in range(len(subsequences)-INPUT_tSIZE-1):
  seq=[subsequences[k] for k in range(i, i+INPUT_tSIZE+1)]
  dfs.append(seq)

print(len(dfs[0]))
print(len(dfs[0][0]))
print(dfs[0][0][datacols])

NUM_CLASSES=2
# %%
# make train data

trainsize=int(len(dfs)*0.70)
validsize=int(len(dfs)*0.15)
testsize=len(dfs)-(trainsize+validsize)

import random
random.shuffle(dfs)

dfs_train=dfs[:trainsize]
dfs_valid=dfs[trainsize:trainsize+validsize]
dfs_test=dfs[trainsize+validsize:]
ds=DummyClass()
ds.x=DummyClass()
ds.y=DummyClass()
ds.x.train=[df[datacols].values for df in dfs_train]
ds.y.train=[df['labels'].values for df in dfs_train]
ds.y.train = tf.keras.utils.to_categorical ( ds.y.train, num_classes=NUM_CLASSES)

ds.x.valid=[df[datacols].values for df in dfs_valid]
ds.y.valid=[df['labels'].values for df in dfs_valid]
ds.y.valid = tf.keras.utils.to_categorical ( ds.y.valid, num_classes=NUM_CLASSES)

ds.x.test=[df[datacols].values for df in dfs_test]
ds.y.test=[df['labels'].values for df in dfs_test]

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

def FitModel(model, train_data,val_data, profile):    
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
                      verbose=1, # 0 no output, 1 full output
                      callbacks=[cp_callback])

  # Save model and history
  model.save(profile.path.model) 
  with open(profile.path.training_history, 'wb') as file_pi:
    import pickle
    pickle.dump(train_history.history, file_pi)
    file_pi.close()
  
  return
profile=DummyClass()

profile.path=DummyClass()
profile.path.root = "."
profile.path.checkpoint_path=profile.path.root+"/model/CRNN_DDoS_Detection/checkpoint"
profile.path.prepdata = profile.path.root+"/prepdata_synth" 
profile.path.modeldata = profile.path.root+"/modeldata"
profile.path.checkpoint_path = profile.path.modeldata+"/ckpt"
profile.path.save_model_path = profile.path.modeldata+"/model"
profile.path.training_history = profile.path.modeldata+'/training_history'

profile.model=DummyClass()
profile.model.name="CRNN_DDoS_Detection"
profile.model.input_size=INPUT_tSIZE
profile.training=DummyClass()
profile.training.EPOCHS=100
profile.training.EVALUATION_INTERVAL=50
profile.training.EPOCHS=100


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


LSTM_UNITS=1
model = MakeCRNNModel(profile.model.inputshape, LSTM_UNITS, NUM_CLASSES, model_name=profile.model.name)
model.summary()
print(profile.model.inputshape)
FitModel(model, train_data, val_data, profile)
# %%
