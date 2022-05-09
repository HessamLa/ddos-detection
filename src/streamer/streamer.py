# %%
import os, sys
from abc import ABCMeta, ABC, abstractmethod
from pickle import NONE
from queue import Empty, Full, Queue
from tkinter.messagebox import NO
from typing import Generator


if __name__=="__main__":
  sys.path.append(os.path.abspath('../'))
  
import utilities as util
from utilities import eprint
from pcapreader.pcapstream import dpkt_pcap2obj
from pcapreader.dpkt_pcap_parser import Parser

# base class
class Streamer (ABC):
  def __init__(self) -> None:
    pass

  @abstractmethod
  def source_generator(self) -> Generator:
    """source_generator() is to be defined in the derived class"""
    pass 

  @abstractmethod
  def summary(self) -> None:
    pass

  @abstractmethod
  def close(self) -> None:
    pass


  def __iter__(self):
    for obj in self.source_generator():
      yield obj

  @classmethod
  def Make(cls, source, source_type, source_format, **kwargs):
    if(source_format=="pcap"):
      return FlowPacketStreamer(source, source_type, **kwargs)
    elif(source_format=="ftd"):
      return FtdObjStreamer(source, source_type, **kwargs)


class PcapStreamer (Streamer):
  def __init__(self) -> None:
      super().__init__()
    
class FlowPacketStreamer (Streamer):
  def __init__(self, source, source_type, buffersize=100000, dontsort=False, filenamefilter=None) -> None:
    """filenamefilter is a function or lamda function for pattern matchin the filename in a directory"""
    # super().__init__(source, buffersize=buffersize)
    if(not filenamefilter):
      filenamefilter=lambda x: x.endswith(".pcap")

    self._bufsize = buffersize
    self._streamer=None         # _streamer will be connected to one PCAP file and stream from that
    self._nxt_streamer_index=0  # each index corresponds to one file
    # initialize paths
    self.files = []
    if(source_type=="file" or source_type=="files"):
      if(isinstance(source, str)):
        self.files=[source]
      elif(isinstance(source, list)):
        self.files=source
      else:
        eprint("source is expected to be a string or a list of strings.")
        raise
    elif (source_type=="dir"):
      for filename in os.listdir(source):
        if(filenamefilter(filename)):
          self.files.append(f"{source}/{filename}")
    
    if(not dontsort):
      self.files.sort()
    self.qufiles = [(i, self.files[i]) for i in range(len(self.files))]
      
    # hook the first streamer
    self._hook_next_streamer()

  def summary(self):
    print("The file(s) to be used:")
    for f in self.files:
      print(f"  {f}")

  def _hook_next_streamer(self):
    if(self._nxt_streamer_index >= len(self.files)):
      self._streamer = None
      return None
    if(len(self.qufiles) == 0):
      self._streamer = None
      return None
    filepath = self.files [self._nxt_streamer_index]
    id, filepath = self.qufiles[0]
    self.qufiles = self.qufiles[1:]
    self._streamer = Parser(filepath, buffersize=self._bufsize) # check memory utilization with buffer size

    print(f"pcap file index:{id} ({len(self.qufiles)} left), {os.path.basename(filepath)}")
    if(self._streamer == None):
      print("Problem opening this file")
    return self._streamer
  
  def close():
    pass
  
  def getnext(self):
    if(self._streamer == None):
      return None
    p = self._streamer.getnext_pkt()
    if(p):
      return p
    else:
      self._hook_next_streamer()
      return self.getnext()    # this might run into non-stoping recursion

  def source_generator(self):
    while(True):
      p = self.getnext()
      if(p):
        yield p
      else:
        break

class FtdObjStreamer (Streamer):
  def __init__(self, source, source_type, buffersize=100000, dontsort=False, pathfilter=None) -> None:
    """pathfilter can be a function or lamda function"""
    # super().__init__(source, buffersize=buffersize)
    if(not pathfilter):
      pathfilter=lambda x: x.endswith(".ftd")

    self._streamer=None
    self._nxt_streamer_index=0

    self.files = []
    if(source_type=="file" or source_type=="files"):
      if(isinstance(source, str)):
        self.files=[source]
      elif(isinstance(source, list)):
        self.files=source
      else:
        eprint("source is expected to be a string or a list of strings.")
        raise
      
    elif (source_type=="dir"):
      for path in os.listdir(source):
        if(pathfilter(path)):
          self.files.append(f"{source}/{path}")
    if(not dontsort):
        self.files.sort()
  def source_generator(self):
    for filepath in self.files:
      # reader = Parser(filepath, buffersize=100000) # check memory utilization with buffer size
      reader = util.pickle_read (filepath)
      while(True):
        ftdobj = reader.get_next ()
        if(ftdobj):
          yield ftdobj
        else:
          break

def test_streamer_base():
  class dummy:
    def __init__(self, value) -> None:
      self.v = value
      self.v2 = value*2
    def __repr__(self) -> str:
        return f"{self.v} {self.v2}"

  class StaticSource:
    def __init__(self, source) -> None:
        self.source=source
        self.front=0
    def __iter__(self):
      return self
    def __next__(self):
      try:
        r = self.source[self.front]
        self.front+=1
        return r
      except IndexError:
        raise StopIteration

  source = StaticSource(source=[dummy(i) for i in range(25)])
  
  streamer = Streamer(source=source, buffersize=15)
  # streamer = Streamer(source=streamer, buffersize=6)
  for obj in streamer:
    print(obj)

def test_pcap_streamer():
  source="/N/u/hessamla/Carbonate/ddos-detection/datasets/cicddos2019/pcap"
  filter=lambda x: "01-12" in x and "69" in x
  filter=None
  # streamer=PcapStreamer(source, source_type="dir", pathfilter=filter)
  streamer=Streamer.Make(source, source_type="dir", source_format="pcap", buffersize=1, pathfilter=filter)

  i=0
  for obj in streamer:
    # print(obj)
    # if(i>10): break
    i+=1
  print("total packets:", i)


def gen():
  for i in range(10):
    if(i==5):
      yield None
    yield i

if __name__=="__main__":

  sys.path.append(os.path.abspath('../'))
  # test_streamer_base()
  test_pcap_streamer()
