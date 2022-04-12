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
from utilities import MakeDataset as md
from utilities import pickle_write, pickle_read, pickle_objects
from datastructures.flowTable import FlowTable



import argparse
parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--pattern', '-p', type=str,   default="SAT-01-12", help='filename pattern')
parser.add_argument('--twin',    '-t', type=float, default=20.0, help='time window')
parser.add_argument('--cmethod', '-m', type=str,   default='catlog2', help='categorization method. catlog2, catlog10, catloge')
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
  lastcid=20
  CID_GROUP = [i+1 for i in range(lastcid)]

print(f"filename pattern:{FILENAME_PATTERN}, time window:{TIME_WINDOW}, cmethod:{CMETHOD}, cfield:{CFIELD}")

def load_data(filename):
  reader = pickle_read(filename)
  data = reader.load()
  reader.close()
  return data


if (CMETHOD == "none"): # only one category
  CID_GROUP = [0] # group of category IDs for this method
else:
  lastcid=20
  CID_GROUP = [i+1 for i in range(lastcid)]


ENTROPIES_DIR = f"./categories-tovictim-{FILENAME_PATTERN}/{CMETHOD}/{CFIELD}/t{TIME_WINDOW:02.0f}"
# files = [f"{ENTROPIES_DIR}/cid{cid}.pkl" for f in os.listdir (ENTROPIES_DIR) if FILENAME_PATTERN in f]
files = [f"{ENTROPIES_DIR}/cid{cid:02d}.pkl" for cid in CID_GROUP]

files.sort()
for f in files[:3]:
  print(f)

data={}
for cid,f in zip(CID_GROUP, files):
  # print(cid, f)
  data[cid] = load_data(f)

# for k,d in data.items():
#   print(k, len(d), d[0]['ts-to'], d[0]['ts-from'])

# %%
maindf={}
for cid, d in data.items():
  df = pd.DataFrame.from_dict(d)
  df["timestamp"] = df['ts-from']
  df.set_index("timestamp", inplace=True)
  df.drop(columns=['ts-to','ts-from'], inplace=True)
  df.fillna(0, inplace=True)
  maindf[cid] = df.copy(deep=True)

print("maindf is ready")
# %%
# # show
# cid=3
# df = maindf[cid].copy()
# # print("duration", max(df.timestamp)-min(df.timestamp))
# print(df.columns)
# axs=df.plot(subplots=True, figsize=(60,40))
# fig = axs[0].get_figure()
# fig.suptitle(f"{ENTROPIES_DIR} cid:{cid}", fontsize=16)
# plt.show()
# fig.savefig(f"img-t{TIME_WINDOW}-cid{cid:02d}.png")
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
  df.drop(columns=['label'], inplace=True)
  newcolnames = {}
  for c in cols:
    newcolnames[c]=f"cid{cid}-{c}"
  df.rename(columns=newcolnames, inplace=True)
  dfs.append(df.copy())

newdf = pd.concat(dfs, axis=1)
# print(newdf.head())
# newdf.head()
# NOW newdf is ready to be fed to a neural network

#%%
from sklearn import preprocessing
le = preprocessing.LabelEncoder()
y = le.fit_transform(newdf['label'].values.ravel())
# y is numpy. convert to ndarray, one-hot


# %%
# print("TESTING OneHotEncoder")
# onehotter = preprocessing.OneHotEncoder(handle_unknown="ignore")
# print(newdf[['label']].head())
# print(newdf[['label']].shape)
# y = onehotter.fit_transform(newdf[['label']].values)
# # %%
# print(type(y))
# print(y.toarray())
# a = y.toarray()
# print(type(a))
# print(y.shape)
# print(a.shape)

  
# print(set(y))


# %%
# from sklearn import preprocessing
# labelencoder = preprocessing.LabelEncoder()
# y = labelencoder.fit_transform(df['label'])
# X = df.copy()
# X.drop(columns=['label'])

# # %%
# SEQ_SIZE=int(60*2/TIME_WINDOW) # 2 minutes
# offset=1
# Xsegs = md.make_subsequence(X[:-offset], seq_size=SEQ_SIZE)
# ysegs = md.make_subsequence(y[offset:], seq_size=SEQ_SIZE)



# %%
df=newdf.copy(deep=True) # renaming
print("df size:", len(df))
forecast_lead=int(60*2/TIME_WINDOW) # 2 minutes
df["label"] = df["label"].shift(-forecast_lead)
df = df.iloc[:-forecast_lead]

# Standardize the features and target
for c in df.columns:
  if("cid" in c):
    mean = df[c].mean()
    stdev = df[c].std()
    if(stdev!=0):
      df[c] = (df[c] - mean) / stdev
# %%
# now convert 'label' to onehot encoding
onehotter = preprocessing.OneHotEncoder(handle_unknown="ignore")
y = newdf[['label']].values
y = onehotter.fit_transform(y)

ycols = onehotter.categories_[0].tolist()
target = [f"label-{c}" for c in ycols]

y = pd.DataFrame(y.toarray(), columns = target)
df = pd.concat([df, y], axis=1) # concatenate onehot encoding to original dataframe

# print(df.head())
df.drop(columns=['label']) # and drop label

# %%
valstart = int(len(df)*0.7)
df_train = df.iloc[:valstart]
df_val = df.iloc[valstart:]

# %%
import torch
from torch.utils.data import Dataset
from torch.utils.data import DataLoader
class SequenceDataset(Dataset):
    def __init__(self, dataframe, target, features, sequence_length=5):
        self.features = features
        self.target = target
        self.sequence_length = sequence_length
        
        print(type(target))
        print(target)
        # from sklearn import preprocessing
        # # self.le = preprocessing.LabelEncoder()
        # # y = self.le.fit_transform(dataframe[target].values.ravel())
        # # print(type(y))
        # print("SequenceDataset")
        # self.onehotencoder = preprocessing.OneHotEncoder(handle_unknown="ignore")
        # print(dataframe[target].head())
        # print(dataframe[target].shape)
        # print(set(dataframe['label'].values))
        # y = self.onehotencoder.fit_transform(dataframe[target].values)
        # print(type(y))
        # y = y.toarray()
        # print(type(y))
        # print(y.shape)
        # # print(y)


        self.y = torch.tensor(dataframe[target].values).float()
        self.X = torch.tensor(dataframe[features].values).float()

        print("X shape", self.X.shape)
        print("y shape", y.shape)
        print("y shape", self.y.shape)
        # input()
    def __len__(self):
        return self.X.shape[0]

    @property
    def shape(self):
        return self.X.shape

    @property
    def featuresize(self):
        return self.X.shape[-1]

    @property
    def targetsize(self):
        return self.y.shape[-1]

    def __getitem__(self, i): 
        if i >= self.sequence_length - 1:
            i_start = i - self.sequence_length + 1
            x = self.X[i_start:(i + 1), :]
        else:
            padding = self.X[0].repeat(self.sequence_length - i - 1, 1)
            x = self.X[0:(i + 1), :]
            x = torch.cat((padding, x), 0)
        return x, self.y[i,:]

features=[c for c in df.columns.tolist() if "cid" in c]
i = 27
sequence_length = int (2*60/TIME_WINDOW) # 2 minutes

train_dataset = SequenceDataset(
    df_train,
    target=target,
    features=features,
    sequence_length=sequence_length
)
X, y = train_dataset[i]
print(X)

test_dataset = SequenceDataset(
    df_val,
    target=target,
    features=features,
    sequence_length=sequence_length
)

batch_size = 20
train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

X, y = next(iter(train_loader))

print("Features shape:", X.shape)
print("Target shape:", y.shape)
       
# %%

from torch import nn

class ShallowRegressionLSTM(nn.Module):
    def __init__(self, num_input, hidden_units, num_output):
        super().__init__()
        self.num_input = num_input  # this is the number of features
        self.hidden_units = hidden_units
        self.num_layers = 1

        self.lstm = nn.LSTM(
            input_size=num_input,
            hidden_size=hidden_units,
            batch_first=True,
            num_layers=self.num_layers
        )

        self.linear = nn.Linear(in_features=self.hidden_units, out_features=num_output)

    def forward(self, x):
        print("forward x.shape:", x.shape)
        batch_size = x.shape[0]
        h0 = torch.zeros(self.num_layers, batch_size, self.hidden_units).requires_grad_()
        c0 = torch.zeros(self.num_layers, batch_size, self.hidden_units).requires_grad_()

        _, (hn, _) = self.lstm(x, (h0, c0))
        out = self.linear(hn[0]).flatten()  # First dim of Hn is num_layers, which is set to 1 above.

        return out

learning_rate = 5e-5
num_hidden_units = 16
num_inputs = train_dataset.featuresize
num_classes = train_dataset.targetsize
print(f"total {num_inputs} features")
print(f"total {num_classes} classes")

model = ShallowRegressionLSTM(num_input=num_inputs, hidden_units=num_hidden_units, num_output=num_classes)
# loss_function = nn.MSELoss()
loss_function = nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)

def train_model(data_loader, model, loss_function, optimizer):
    num_batches = len(data_loader)
    total_loss = 0
    model.train()

    truepos=0
    total=0
    total_acc = 0
    for X, y in data_loader:
        output = model(X)
        print("training:", X.shape, y.shape, output.shape)
        loss = loss_function(output, y)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        total_loss += loss.item()
        total_acc += (output==y).sum().float()/y.size(0)

    avg_loss = total_loss / num_batches
    avg_acc = total_acc / num_batches
    return avg_loss, avg_acc

def test_model(data_loader, model, loss_function):

    num_batches = len(data_loader)
    total_loss = 0

    model.eval()
    total_acc = 0
    with torch.no_grad():
        for X, y in data_loader:
            output = model(X)
            print("testing:", X.shape, y.shape, output.shape)
            total_loss += loss_function(output, y).item()
            total_acc += (output==y).sum().float()/y.size(0)

    avg_loss = total_loss / num_batches
    avg_acc = total_acc / num_batches
    return avg_loss, avg_acc


print("Untrained test\n--------")
test_model(test_loader, model, loss_function)
print()

for ix_epoch in range(100):
    loss_train, acc_train=train_model(train_loader, model, loss_function, optimizer=optimizer)
    loss_test, acc_test=test_model(test_loader, model, loss_function)
    print(f"Epoch {ix_epoch:03d}   train loss:{loss_train:6.3f}   test loss:{loss_test:6.3f}")
    
# %%
def predict(data_loader, model):

    output = torch.tensor([])
    model.eval()
    with torch.no_grad():
        for X, _ in data_loader:
            y_star = model(X)
            output = torch.cat((output, y_star), 0)

    return output


train_eval_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=False)

ystar_col = "Model forecast"
df_train[ystar_col] = predict(train_eval_loader, model).numpy()
df_val[ystar_col] = predict(test_loader, model).numpy()

train_acc = torch.sum(df_train[ystar_col] == df_train[target])
final_train_acc = train_acc/len(df)
print("Train accuracy", final_train_acc)

val_acc = torch.sum(df_val[ystar_col] == df_val[target])
final_val_acc = val_acc/len(df)
print("Validation accuracy", final_val_acc)

print("prediction done")
df_out = pd.concat((df_train, df_val))[[target, ystar_col]]
print("concat done")

# for c in df_out.columns:
#     df_out[c] = df_out[c] * target_stdev + target_mean

print(df_out)