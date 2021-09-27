import os
import sys
import csv
import subprocess
import gc
import dpkt
# from pcapreader.pcapstream import *
from pcapreader.pcapstream import dpkt_pcap2obj
# from dpkt_pcap_parser import Parser
import time
import math


import utilities as util
from utilities import eprint
from utilities import HashCollection
from utilities import COLOR_CODE as C

from datastructures.structures import FTDObj
from datastructures.flowTable import FlowEntry
from datastructures.flowTable import FlowTable

def Parse_Csv (filepath):
  def conv(s):
    try:
      s=float(s)
    except ValueError:
      pass  
    return s

  def read_csv (filepath):
    with open (filepath, 'r') as csvfile:
      packets = csv.reader(csvfile, delimiter=',')
      for p in packets:
        yield [ conv(i) for i in p ]

  packets = list (read_csv(filepath))


  # Get indices for each column label
  for i in range (len (packets[0])):
    if   (packets[0][i] == 'SrcIp'):    iSrcIp = i
    elif (packets[0][i] == 'DstIp'):    iDstIp = i
    elif (packets[0][i] == 'Protocol'):   iProto = i
    elif (packets[0][i] == 'SrcPrt'):   iSrcPrt = i
    elif (packets[0][i] == 'DstPrt'):   iDstPrt = i
    elif (packets[0][i] == 'Time_Epoch'): iTime = i
    elif (packets[0][i] == 'TTL'):    iTtl = i
    elif (packets[0][i] == 'FrameLen'):   iFrameLen = i

  return packets, [iTime, iSrcIp, iDstIp, iProto, iSrcPrt, iDstPrt, iTtl, iFrameLen]

def stripright (s, subs):
  if s.endswith(subs):
    s = s[:-len(subs)]
  return s

class Switch_Class:
  def __init__ (self, id=0, name=None):
    eprint ('New switch Initiated.  ID: {}   name: {}'.format (id, name))
    name = stripright (name, '.pcap')
    name = stripright (name, '.ftd')
    self.name = name
    self.id = id
    
    self.time = None
    self.next_pkt_id = 0 # ID of the next immediate packet not processed so far. Note the first row of packets is for columns labels

    self.__ftbl = FlowTable (id=self.id, name=self.name)
    self.__newftbl = None # New entries; This is a temporary flow table that needs to be reset at the start of each window
    self.__drtftbl = None # Dirty entries; This is a temporary flow table that needs to be reset at the start of each window
    self.__drtindx = set() # Set of indices of the dirty flow table entries; It must be reset at the start of each window
    return

  def update_properties (self, timewin=None, time=None):
    if timewin: self.timewin = timewin
    if time: self.time = time
    return

  def send_packets (self, packets): # this method sends packets to the controller
    self.packets = packets
    self.__process (packets)
    return

  @property
  def flow_table (self, dirty=False, new=False, pktCnt=None, lg2pktCnt=None):
    # return self.__flows
    if (dirty == False and new == False):
      return self.__ftbl
    
    if (dirty == True):
      ftbl = FlowTable (name=self.name+'-DIRTY')
      for k in self.__ftbl.keys():
        if self.__ftbl[k].dirty == True:
          ftbl[k] = self.__ftbl[k]

    elif (new == True):
      ftbl = FlowTable (name=self.name+'-NEW')
      for k in self.__ftbl.keys():
        if self.__ftbl[k].new == True:
          ftbl[k] = self.__ftbl[k]

    elif (pktCnt != None):
      ftbl = FlowTable (name=self.name+'-'+str(pktCnt)+'FLOWS')
      for k in self.__ftbl.keys():
        if self.__ftbl[k].dif_cnt == pktCnt:
          ftbl[k] = self.__ftbl[k]

    elif (lg2pktCnt > 0):
      if (lg2pktCnt >= 9): name=self.name+'-'+str(pktCnt)+'+Lg2FLOWS'
      else:                name=self.name+'-'+str(pktCnt)+'Lg2FLOWS'
      ftbl = FlowTable (name=name)
      for k in self.__ftbl.keys():
        cnt = self.__ftbl[k].dif_cnt
        if (cnt == 0): continue
        i = int (math.log2(cnt)) + 1
        if (i == lg2pktCnt or (lg2pktCnt >= 9 and i >= 9)):
          ftbl[k] = self.__ftbl[k]
    return ftbl

  # @property
  # def flow_table_new (self):
  #   if (self.__newftbl != None):
  #     return self.__newftbl
  #   self.__newftbl = FlowTable (id=self.id, name=self.name+'_NEW_ENTRIES')
  #   # for h in self.__ftbl.keys ():
  #   #   f = self.__ftbl [h]
  #   #   if (f.new == True):
  #   #     self.__newftbl [h] = f
  #   for h in self.__ftbl.newKeys:
  #     self.__newftbl [h] = self.__ftbl [h]
  #   return self.__newftbl

  # @property
  # def flow_table_dirty (self):
  #   t1 = time.time()
  #   if (self.__drtftbl != None):
  #     return self.__drtftbl
  #   self.__drtftbl = FlowTable (id=self.id, name=self.name+'DIRTY_ENTRIES')
  #   # for h in self.__ftbl.keys ():
  #   #   f = self.__ftbl [h]
  #   #   if (f.dirty == True):
  #   #     self.__drtftbl [h] = f
  #   for h in self.__ftbl.dirtyKeys:
  #     self.__drtftbl [h] = self.__ftbl [h]    
  #   print ('switch.flow_table_dirty prep time {}{:.2f}{}'.format (C.RED, time.time() - t1, C.NC))
  #   return self.__drtftbl

  @flow_table.setter
  def flow_table (self, ftbl):
    # self.__flows = ftbl
    self.__ftbl = ftbl
    return

  def reinit (self):
    """Reset flags of all current entries
    """
    for flow in self.__ftbl:
      flow.reset ()
    self.__newftbl = None
    self.__drtftbl = None
    self.__drtindx = set()

  # NEEDS OPTIMIZATION
  def maintain_flowtable (self, timelim=None, idle_timeout=None,\
    sip=None, dip=None, sport=None, dport=None, proto=None):
    """Remove entries from the table according to these criteria."""
    t1 = time.time ()
    for k in list (self.flow_table.keys()):
      f = self.flow_table [k]
      if ((not timelim      or timelim > f.ts)  and \
          (not idle_timeout or idle_timeout < self.time - f.ts) and \
          (not sip          or sip == f.sip)   and \
          (not dip          or dip == f.dip)   and \
          (not sport        or sport == f.sport) and \
          (not dport        or dport == f.dport)\
         ):
        self.flow_table.remove_entry (k)
    print (C.RED, self.name, "Table maintenance time", time.time() - t1, C.NC)
    
  def __process (self, packets=None):
    # # All previous stats must be marked as old
    # for h in self.stats:
    #   self.stats [h].reinit_window()

    if packets == None:
      eprint ('No more packets left to process')
      return

    for p in packets:
      # # print (p)
      # h = hash (str([p.sip, p.dip, p.proto, p.sport, p.dport])) # Make a hash of packet

      # if h not in self.__ftbl.keys():
      #   self.__ftbl [h] = FlowEntry(h, p)
      # else:
      #   self.__ftbl [h].add (ts=p.ts, difCnt=1, difLen=p.len)
      # OR WE COULD IMPLEMENT THIS:
      self.__ftbl.add_packet (p)


class Switch_Driver:
  switchCount = 0
  def __init__(self, filename, filetype, dirpath='.',\
    timewin=10.0, protocol_include=None, idle_timeout=300): # protocol is a comma-separted list
    
    self.idle_timeout = idle_timeout
    Switch_Driver.switchCount += 1

    self.protocols = None 
    if (protocol_include):
      self.protocols = protocol_include
    eprint ("Switch driver initiated. ID: ", Switch_Driver.switchCount,\
        "Protocols: ", self.protocols,
        "Source Type:", filetype)
    
    self.switch =  Switch_Class(id=Switch_Driver.switchCount, name=filename)

    self.filename=filename
    self.filetype=filetype
    filepath = os.path.join(dirpath, filename)
    
    self.timewin = float (timewin)
    self.time = 0.0

    if (self.filetype == 'pcap'):
      self.pcap_reader = dpkt_pcap2obj (filepath)
      
      self.p = self.pcap_reader.get_next_packet () # next packet to be processed in the system
      self.next_pkt_id = 1 # 0th row of the file is expected to be column names
      self.time = sys.float_info.max  
      if (self.p):
        self.time = float (self.p.ts) # time of the first packet
        self.switch.update_properties (time=self.time)

    elif (self.filetype == 'ftd'):
      self.ftable_img_reader = util.pickle_read (filepath)

    self._done=False  # This is set when there is no more packets or netshots left to process
    return

  @property
  def is_done (self):
    return self._done

  # NEEDS OPTIMIZATION
  def progress (self, timelim=None, timewin=None):
    """Progress state of the switch by reading packets from pcap source which have timestamp
    before time 'timelim' (time limit). If timelim is not given, then it is calculated by current time
    of the switch + time window (self.time + self.timewin). If 'timelim' is not given, then self.timewin'
    can also be updated at each call of progress() by setting up the 'timewin' argument."""

    if (self._done == True):
      # print ('No more packets left to progress:', self.filename)
      return
    if (timelim):
      if (timelim <= self.time):
        eprint ("ERR: time limit. It must be larger than current time of switch.")
        eprint ("switch_driver.progress()")
        exit()
      self.timewin = timelim - self.time
    elif (timewin):
      self.timewin = float(timewin)

    t1 = time.time ()
    st = 0
    self.switch.reinit()
    if (self.filetype == 'pcap'):
      for packets in self.__read_pcaps(self.time + self.timewin):
        t2 = time.time()
        self.switch.send_packets (packets=packets)
        t3 = time.time()
        st += t3-t2
        # eprint ('{} @{:.2f}   from {} to {}'. format (self.filename, t, self.next_pkt_id, i))
        self.next_pkt_id += len (packets)
      self.time += self.timewin
      print ('switch.progress(): switch.send_packets() time={}{:.2f}{}, total time={}{:.2f}{}'.format(C.YLW, st, C.NC, C.YLW, t3-t1, C.NC))
    elif (self.filetype == 'ftd'):
      for ftbl in self._read_ftable (self.time + self.timewin):
        t2 = time.time()
        self.switch.flow_table.add_table (ftbl)
        st += time.time()-t2
      t3 = time.time()
      print ('switch.progress(): switch.flow_table.add_table() time={}{:.2f}{}, ReadFtbl time={}{:.2f}{}'.format(C.YLW, st, C.NC, C.YLW, t3-t1-st, C.NC))

    #   if (not hasattr(self, 'nshot')):
    #     self.nshot = self._read_ftable (self.time + self.timewin)
    #     self.dumptype, self.protocols, self.nswin, self.nstime, self.nsftbl = FTDObj.unpack_obj (self.nshot)
    #     # nstime: netshot switch time
    #     # nswin: netshot time window
    #     print (C.RED, timelim, self.time, self.timewin, C.NC)
    #     if (self.time < self.nstime):
    #         self.time = self.nstime
    #   timelim = self.time + self.timewin

    #   while (self.nstime + self.nswin < timelim):
    #     print (C.RED, self.nstime, self.nswin, timelim, C.NC)
    #     if (self.dumptype==FTDObj.DumpType.NEW_FLOWTABLE): # update the flowtable if there is a change.
    #       self.switch.flow_table.add_table (self.nsftbl)
    #     self.dumptype, self.protocols, self.nswin, self.nstime, self.nsftbl = self._read_ftable ()

      self.time += self.timewin
      
    self.switch.update_properties (time = self.time)

    s1 = self.switch.flow_table.size
    self.switch.maintain_flowtable (idle_timeout=self.idle_timeout)
    s2 = self.switch.flow_table.size
    print (">>>switch.progress(): "+str(s1)+" - "+str(s2)+" = \033[0;31m"+str(s1-s2)+"\033[0m<<<<<")
    return

  def __read_pcaps (self, timelim):
    # print (">>>>> switch.__read_pcaps()", self.filename, 'continuing from time', self.time)
    packets=[]
    totalcnt = 0
    
    # t=-1 # COMMENT OUT
    # str = "{}".format(self.p .ts) # COMMENT OUT
    dif = 0
    try:
      while (self.p and self.p.ts < timelim):
        if ( self.protocols==None ):  # If no protocol is given, then accept all packets
          packets.append (self.p)
        elif (self.p.proto in self.protocols): # Otherwise, accept only the recognized packets
          # print (self.protocols, self.p.proto, self.p.sport, self.p.dport)
          packets.append (self.p)
        # t = self.p.ts - self.time # COMMENT OUT
        t0 = time.time()
        self.p = self.pcap_reader.get_next_packet()
        t1 = time.time()
        dif += t1-t0
        if (len(packets) >= 100000):
          totalcnt += len (packets)
          yield packets
          packets = []
    except:
      print ("switch.__read_pcaps(): packet type is", type(self.p))
      exit()

    if (self.p==None): self._done = True


    totalcnt += len (packets)
    if (totalcnt > 1):
      print (self.filename, "|Pkt Cnt:", totalcnt, '|exec time diff:', "{:.3f}".format(dif)) # COMMENT OUT
    if dif > 1:
      RED='\033[0;31m'
      NC='\033[0m' # No Color
      print (RED, '  Time elapsed reading packets from pcap:', dif, NC)
    
    yield packets
    return

  def _read_ftable (self, timelim):
    # t1 = time.time()
    # obj = self.ftable_img_reader.get_next ()
    # return obj

    # t2 = time.time()
    # return FTDObj.unpack_obj (obj)
    # dumptype, protocols, timewin, t, flow_table = FTDObj.unpack_obj (obj)
    # t3=time.time()
    # print ("switch._read_ftabl: tReadFTD=%.2f tUnpack=%.2f"%(t2-t1, t3-t2))
    # print (">>>>>>> switch.read_ftable", dumptype, protocols, timewin, t, flow_table)
    if (not hasattr(self, 'nshot')):
      self.nshot = self.ftable_img_reader.get_next ()
      if (self.nshot == None):
        self._done = True
        return
      self.dumptype, self.protocols, self.nswin, self.nstime, self.nsftbl = FTDObj.unpack_obj (self.nshot)
      # nstime: netshot switch time
      # nswin: netshot time window
      print (C.RED, timelim, self.time, self.timewin, C.NC)
      if (self.time == 0):
        self.time = self.nstime
        timelim = self.time + self.timewin

    print (C.RED, "from         win  timeLimit(sec)", C.NC)
    while (self.nstime + self.nswin < timelim):
      print (C.RED, self.nstime, self.nswin, timelim, C.NC)
      if (self.dumptype==FTDObj.DumpType.NEW_FLOWTABLE): # update the flowtable if there is a change.
        yield self.nsftbl
      self.nshot = self.ftable_img_reader.get_next ()
      if (self.nshot == None):
        self._done = True
        break
      self.dumptype, self.protocols, self.nswin, self.nstime, self.nsftbl = FTDObj.unpack_obj (self.nshot)
    return
    # return dumptype, protocols, timewin, t, flow_table

