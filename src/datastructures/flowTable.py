from .structures import AssociativeEntry
from .structures import AssociativeTable
from .structures import flow_packet

from utilities import eprint
from utilities import getflowcat
import math

def make_categoric_ftables (ftbl, cat_method, K=None, categories=None):
    """Categories:
    Lg2pktCnt: 0, 1, 2, ... (K-1)+
    State: new, old, any
    """
    _new=0
    _prv=1
    _any=2
    offset_new = _new*K
    offset_prv = _prv*K
    offset_any = _any*K
    
    method_ids = {"log2pktcnt"   :0,
                  "log10pktcnt"  :1,
                  "log2pktlen"   :2,
                  "log10pktlen"  :3,
                  "custom_pktcnt":4,
                  "custom_pktlen":5}
    cat_method = method_ids [cat_method] # convert from string to corresponding integer

    ftbls = [None for i in range (K*3)]
    for i in range (0, K):
      name = "cftbl-new-k"+str(i - _new*K)
      ftbls[i] = FlowTable (id=i+1, name=name)
    for i in range (K, K*2):
      name = "cftbl-prv-k"+str(i - _prv*K)
      ftbls[i] = FlowTable (id=i+1, name=name)
    for i in range (K*2, K*3):
      name = "cftbl-any-k"+str(i - _any*K)
      ftbls[i] = FlowTable (id=i+1, name=name)

    for h in ftbl.newKeys: # Make categoric flows tables of new flows
      f = ftbl [h]
      k = getflowcat (f, cat_method, max_cat=K-1)
      ftbls [k + offset_new][h] = f # OR SHOULD I USE f.copy()?
      ftbls [k + offset_any][h] = f

    for h in (ftbl.dirtyKeys - ftbl.newKeys): # Make categoric flows tables of non-new flows
      f = ftbl [h]
      k = getflowcat (f, cat_method, max_cat=K-1)
      ftbls [k + offset_prv][h] = f
      ftbls [k + offset_any][h] = f

    s = 0
    for ftbl in ftbls:
      s += ftbl.size
    return ftbls

def make_categoric_ftbl_keys (ftbl, K, mode='log2pktcnt'):
  """
  Given a ftbl, it returns lists of keys that in categories (classes).
  Lg2pktCnt: 0, 1, 2, ... (K-1)+
  State: new, old, any
  """
  def mkname (state, category):
    if (state == 0):
      return "new-k"+str(category)
    elif (state == 1):
      return "prv-k"+str(category)
    elif (state == 2):
      return "any-k"+str(category)

  _new = 0
  _prv = 1
  _any = 2

  keys = {}

  for k in range (K):
    name = mkname (_new, k)
    keys [name] = []
  for k in range (K):
    name = mkname (_prv, k)
    keys [name] = []
  for k in range (K):
    name = mkname (_any, k)
    keys [name] = []
    
  for h in ftbl.newKeys: # Make categoric list of flows keys of new flows
    k = getflowcat (ftbl [h], mode, max_cat=K-1)
    keys [mkname(_new,k)].append (h)
    keys [mkname(_any,k)].append (h)

  for h in (ftbl.dirtyKeys - ftbl.newKeys): # Make categoric list of flows keys of non-new flows
    k = getflowcat (ftbl [h], mode, max_cat=K-1)
    keys [mkname(_prv,k)].append (h)
    keys [mkname(_any,k)].append (h)

  s = 0
  for h in keys:
    s += len (keys[h])
  print ("make_categoric_ftbl_keys()")
  print ("TOTAL ENTRIES", s)
  return keys   

class FlowEntry (AssociativeEntry):
  """A flow entry in the flow table. Creation of the flow requires a first packet.
  Subsequent updates to the entry will be additive, by adding to its counting attributes."""
  def __init__ (self, hashCode, p):
    """This function, gets a packet
    hashCode is the signature of the flow. p is an flow_packet pertaining to the flow.
    """

    AssociativeEntry.__init__ (self, key=hashCode, dirty=True)
    self.new   = True # New Flow flag. True, if this is a new flow entry

    self.ts   = p.ts  # time-stamp, records latest modifcation time of this flow entry
    self.ts0  = p.ts  # time-stamp, records previous modification time 
    self.tc   = p.ts  # time created, records time of creating this flow entry. Once set, this variable shall not be modified
    self.saddr  = p.saddr
    self.daddr  = p.daddr
    self.proto  = p.proto
    self.sport  = p.sport
    self.dport  = p.dport
    
    # counting attributes
    self.pktCnt = 1     # Total packet count
    self.pktLen = p.len # Total packet length

    self.prvCnt = 0     # Total packet count in the previous window
    self.prvLen = 0     # Total packet length in the previous window

    self.req_freq    = None # Request frequency
    self.req_phase_shift = None # Request phase shift

  def reset (self):
    self.dirty = False
    self.new   = False

    self.prvCnt = self.pktCnt
    self.prvLen = self.pktLen
    return

  def add (self, ts, difCnt, difLen):
    """add the parameters of pkt or entry to an existing entry"""
    self.dirty = True

    self.ts0  = self.ts
    self.ts   = ts
    self.pktCnt += difCnt
    self.pktLen += difLen
    return

  @property
  def age (self):
    """Returns age of this flow: timestamp of latest packet - time of flow creating in flow table
    """
    return self.ts - self.tc

  @property
  def dif_cnt (self):
    """ Total packet count in the current window """
    return self.pktCnt - self.prvCnt

  @property
  def dif_len (self):
    """ Total packet length in the current window """
    return self.pktLen - self.prvLen

  def printInfo (self):
    print ("key:", self.key)
    print ("dirty:", self.dirty)
    
    print ("is new:", self.new)
    print ("saddr daddr proto sport dport:",\
      self.saddr, self.daddr, self.proto, self.sport, self.dport)
    print ("pkt_cnt pkt_len:", self.pktCnt, self.pktLen)


class FlowTable (AssociativeTable):
  def __init__ (self, id=0, name=None, entry_max_age=10):
    AssociativeTable.__init__ (self, id, name)
    self.max_age = entry_max_age # entries older than max_age can be removed
    self.__totalpktCnt = 0
    self.__totalpktLen = 0
    self.__dirty_keys = set () # Keys of all dirty entries in the flow table
    self.__new_keys = set () # Keys of the new entries. This set is a subset of self.__dirty_keys
    return

  def get_summary(self, oneliner=True) -> str:
    if(oneliner):
      r=f"{self.name} cnt:{self.__totalpktCnt} len:{self.__totalpktLen} "
      r+=f"all:{len(self.tbl)} new:{len(self.__new_keys)} dirty:{len(self.__dirty_keys)}"  
    else:
      r =f"Name:{self.name}\n"
      r+=f"Packet count: {self.__totalpktCnt}\n"
      r+=f"Packet length: {self.__totalpktLen}\n"
      r+=f"Total entries: {len(self.tbl)}\n"
      r+=f"Dirty entries: {len(self.__dirty_keys)}\n"
      r+=f"New entries: {len(self.__new_keys)}\n"
    return r

  def summary(self) -> None:
    print(self.get_summary(oneliner=False))

  def __repr__(self) -> str:
    return self.get_summary()
  
  def __populate_keys_sets (self):
    if (len (self.__new_keys) == 0): # IF new_keys is empty, THEN populate it
      if (len (self.__dirty_keys) == 0): # IF dirty_keys is empty, THEN populate it too
        for h, f in self.items ():
          if f.new == True: # A new entry is also dirty
            self.__new_keys.add (h)
            self.__dirty_keys.add (h)
          elif f.dirty == True:
            self.__dirty_keys.add (h)
      else: # IF dirty__keys is NOT empty, THEN populate new_keys based on dirty_keys
        for h in self.__dirty_keys:
          if self [h].new == True:
            self.__new_keys.add (h)
    return

  @property
  def dirtyKeys (self):
    """Keys of dirty entries"""
    if (len (self.__dirty_keys) == 0):
      self.__populate_keys_sets ()
    return self.__dirty_keys

  @property
  def newKeys (self):
    """Keys of new entries"""
    if (len (self.__new_keys) == 0):
      self.__populate_keys_sets ()
    return self.__new_keys

  @property
  def oldKeys (self):
    """Keys of non-new dirty entries"""
    return self.dirtyKeys - self.newKeys

  @property
  def pktCnt (self):
    return self.__totalpktCnt

  @property
  def pktLen (self):
    return self.__totalpktLen

  def clear (self):
    self.__dirty_keys = set ()
    self.__new_keys = set ()
    super().clear ()
    return

  def set_dirty_keys (self, dkeys):
    self.__dirty_keys = dkeys
    return

  def set_new_keys (self, nkeys):
    self.__new_keys = nkeys
    return

  def add_packet (self, p):
    """Adds the packet p to the flow table. Returns key of the corresponding entry"""
    # print(p)
    # h = hash (str([p.saddr, p.daddr, p.proto, p.sport, p.dport]))
    # print(h)
    # exit()
    h = hash (str([p.saddr, p.daddr, p.proto, p.sport, p.dport])) # Make a hash of packet
    try:
      self.tbl [h].add (p.ts, 1, p.len)
    except KeyError: # This is a new entry
      self.tbl [h] = FlowEntry(h, p)
      self.__new_keys.add (h)

    self.__dirty_keys.add (h)
    self.__totalpktCnt += 1 
    self.__totalpktLen += p.len
    return h
    
    # if h not in self._tbl:
    #   self.tbl [h] = FlowEntry(h, p)
    # else:
    #   self.tbl [h].add (p.ts, 1, p.len)
    # return

  def add_table (self, t):
    if (self.size == 0):
      self.maketbl (t.tbl)
      return

    for h, f in t.items():
      try:
        self.tbl[h].add (f.ts, f.dif_cnt, f.dif_len)
      except KeyError:
        self.tbl[h] = f.copy()
      if self.tbl[h].new == True: # New entries are also dirty
        self.__new_keys.add (h)
        self.__dirty_keys.add (h)
      elif self.tbl[h].dirty == True:
        self.__dirty_keys.add (h)
        
      self.__totalpktCnt += f.dif_cnt
      self.__totalpktLen += f.dif_len
    return

  def reset (self):
    for f in self.tbl.values():
      f.__totalpktCnt = 0
      f.__totalpktLen = 0
    self.__dirty_keys = set ()
    self.__new_keys = set ()
    super().reset ()
    return

  def remove_entry (self, h):
    try:
      del self.tbl[h]
      self.__dirty_keys.discard (h)
      self.__new_keys.discard (h)
    except KeyError:
      eprint (f"ERR: Could not remove entry {h} from the table {self.name}.")
      pass
    return

  def clone (self, clone_type=None):
    """Returns a clone of this table or its subset according to the subset type.
    Types are the following:
    None:  current flowtable
    dirty: flowtable with only dirty flows
    new:   flowtable with only new flows
    old:   flowtable with dirty and old flows
    """
    if (clone_type == None):
      ftbl = FlowTable (id=self.id, name=self.name+'-CLONE')
      for h in self.newKeys:
        ftbl [h] = self [h]
      ftbl.set_dirty_keys (self.dirtyKeys) # set of new keys is a subset of dirty keys
      ftbl.set_new_keys (self.newKeys)
      
      
    elif (clone_type == "new"):
      ftbl = FlowTable (id=self.id, name=self.name+'-NEW_ENTRIES')
      for h in self.newKeys:
        ftbl [h] = self [h]
      ftbl.set_dirty_keys (self.newKeys) # set of new keys is a subset of dirty keys
      ftbl.set_new_keys (self.newKeys)
      
    elif (clone_type == "dirty"):
      ftbl = FlowTable (id=self.id, name=self.name+'-DIRTY_ENTRIES')
      for h in self.dirtyKeys:
        ftbl [h] = self [h]
      ftbl.set_dirty_keys (self.dirtyKeys) 
      ftbl.set_new_keys (self.newKeys)
      
    else:
      eprint ("ERR: Wrong clone_type:", clone_type)
      raise Exception

    return ftbl

  def entropy (self):
    return


  # def remove_prv (self):
  #   """Removes old entries"""
  #   for h in self.tbl:
  #     if (self.tbl[h].age > self.max_age ):
  #       self.tbl.pop (h)
  #   return

  # def __iter__ (self):
  #   return self
  
  # def __next__ (self):
  #   for f in self.tbl.values ():
  #     yield f
  #   return


class StatsFlowTable:
  def __init__ (self):
    return

  @classmethod
  def stats (cls, ftbl, K=7):
    N = ftbl.size
    if (N==0):
      print ("Flow table is empty. No statistics available.")
    cremf = 0 # number of removed flows

    cntf = [0 for i in range (K)] # number of K-packet flows, k is 0,1,...,5,6+
    cnewf = [0 for i in range (K)] # number of new K-packet flows
    s_agef = [0 for i in range (K)] # sum age of K-packet flows
    s_agef2= [0 for i in range (K)] # sum age of K-packet flows, squared
    s_pktcf = [0 for i in range (K)]# sum packet count of K-packet flows
    s_pktcf2= [0 for i in range (K)]# sum packet count of K-packet flows, squared
    s_pktlf = [0 for i in range (K)]# sum packet length of K-packet flows
    s_pktlf2= [0 for i in range (K)]# sum packet length of K-packet flows, squared
    s_pktprf = [0 for i in range (K)]# sum packet period (1/frequency) of K-packet flows, squared
    s_pktprf2= [0 for i in range (K)]# sum packet period (1/frequency) of K-packet flows, squared
    s_rpktcfage = [0 for i in range (K)]# sum ratio of packet count to flow age
    s_rpktcfage2= [0 for i in range (K)]# sum ratio of packet count to flow age, squared
    
    for f in ftbl:
      if (f.dif_cnt < 1):
        k = 0
      else:
        k = int (math.log2 (f.dif_cnt))+1
      if k >= K: k=K-1

      cntf [k] += 1
      if f.new: cnewf [k] += 1

      s_agef  [k] += f.age
      s_agef2 [k] += f.age**2
      s_pktcf [k] += f.dif_cnt
      s_pktcf2[k] += f.dif_cnt**2
      s_pktlf [k] += f.dif_len
      s_pktlf2[k] += f.dif_len**2
      s_pktprf [k] += f.ts - f.ts0
      s_pktprf2[k] += (f.ts - f.ts0)**2
      if (f.age == 0):
        s_rpktcfage [k] += f.dif_cnt/0.01 
        s_rpktcfage2[k] += (f.dif_cnt/0.01)**2 
      else:
        s_rpktcfage [k] += f.dif_cnt/f.age
        s_rpktcfage2[k] += (f.dif_cnt/f.age)**2
    
    s_pktcnt = sum (s_pktcf) # sum packet count
    s_pktcnt2= sum (s_pktcf2)# sum packet count squared
    s_pktlen = sum (s_pktlf) # sum packet length
    s_pktlen2= sum (s_pktlf2)# sum packet length squared

    def std (S2, Mu, N):
      """
      S2: Sum of squared values
      Mu: Mean of values (sum of values / N)
      N : Total number of values
      """
      if (N == 0):
        return 0
      var = S2/N - Mu**2
      if abs(var) < 0.001:
        return 0
      return math.sqrt (var)
    
    if (N == 0):
      avg_pktcnt = 0 # Mean packet count
      avg_pktlen = 0 # Mean packet length
    else:
      avg_pktcnt = s_pktcnt/N # Mean packet count
      avg_pktlen = s_pktlen/N # Mean packet length
    
    std_pktcnt = std (s_pktcnt2, avg_pktcnt, N) # Std packet count
    std_pktlen = std (s_pktlen2, avg_pktlen, N) # Std packet length

    avg_agef = [0 for i in range (K)] # Mean age of K-packet flows
    std_agef = [0 for i in range (K)] # Std age of K-packet flows
    avg_pktlf = [0 for i in range (K)] # Mean packet length of K-packet flows
    std_pktlf = [0 for i in range (K)] # Std packet length of K-packet flows
    avg_pktprf = [0 for i in range (K)] # Mean packet period of K-packet flows
    std_pktprf = [0 for i in range (K)] # Std packet period of K-packet flows
    avg_rpktcfage = [0 for i in range (K)] # Mean ratio of packet cnt to flow age of K-packet flows
    std_rpktcfage = [0 for i in range (K)] # Std ratio of packet cnt to flow age of K-packet flows

    for k in range (K):
      n = cntf[k]
      if (n == 0):
        avg_agef  [k] = 0
        std_agef  [k] = 0
        avg_pktlf [k] = 0
        std_pktlf [k] = 0
        avg_pktprf [k] = 0
        std_pktprf [k] = 0
        avg_rpktcfage [k] = 0
        std_rpktcfage [k] = 0
      else:
        avg_agef   [k] = s_agef [k]/n
        std_agef   [k] = std (s_agef2 [k], avg_agef [k], n)
        avg_pktlf  [k] = s_pktlf[k]/n
        std_pktlf  [k] = std (s_pktlf2 [k], avg_pktlf [k], n)
        avg_rpktcfage [k] = s_rpktcfage [k]/n
        std_rpktcfage [k] = std (s_rpktcfage2 [k], avg_rpktcfage [k], n)
        # don't consider new flows for averaging 1-pkt periods
        if (k==1): n = n-cnewf[k]
        if (n==0):
          avg_pktprf [k] = 0
          std_pktprf [k] = 0
        else:
          avg_pktprf [k] = s_pktprf [k]/n
          std_pktprf [k] = std (s_pktprf2[k], avg_pktprf[k], n)

    stat = [
      K,         # K Number of k-packet flows, k=0,1,...,K-1
      cntf, cnewf,   # Number of k-pkt flows, number of new flows
      avg_pktcnt, std_pktcnt, # Mean and std of total packet count
      avg_pktlen, std_pktlen, # Mean and std of total packet length
      avg_pktlf , std_pktlf,  # Mean and std of packet length for k-pkt flows
      avg_pktprf, std_pktprf,  # Mean and std of packet period for k-pkt flows
      avg_agef, std_agef  # Mean and std of age of k-pkt flows
      ]       
    return stat

  @classmethod
  def print (cls, stats):
    from utilities import COLOR_CODE as C
    [
      K,         # K Number of k-packet flows, k=0,1,...,K-1
      cntf, cnewf,   # Number of k-pkt flows, number of new flows
      avg_pktcnt, std_pktcnt, # Mean and std of total packet count
      avg_pktlen, std_pktlen, # Mean and std of total packet length
      avg_pktlf , std_pktlf,  # Mean and std of packet length for k-pkt flows
      avg_pktprf, std_pktprf,  # Mean and std of packet period for k-pkt flows
      avg_agef, std_agef  # Mean and std of age of k-pkt flows
    ] = stats

    print ("FlowTable Stats")
    print ("Number of total flows  \033[0;32m",sum(cntf), "\033[m")
    print ("Number of new flows    \033[0;32m",sum(cnewf), "\033[m")
    print ("Number of modified flows \033[0;32m",sum(cntf[1:]), "\033[m")

    print ("Packet count  avg \033[0;32m","{:7.2f}".format (avg_pktcnt), "\033[m")
    print ("        std \033[0;32m","{:7.2f}".format (std_pktcnt), "\033[m")
    print ("Packet length avg \033[0;32m","{:7.2f}".format (avg_pktlen), "\033[m")
    print ("        std \033[0;32m","{:7.2f}".format (std_pktlen), "\033[m")

    print ("            "+C.ulin+" flowCnt  newCnt  avgAge  stdAge avgPLen stdPLen avgPPrd stdPPrd"+C.NC)
    for k in range (K):
      n = cntf[k]
      if (k == K-1):
        s = ' x-pkt flow|'
      else:
        s = '{:2d}-pkt flow|'.format (k)
      s += ' \033[0;32m{:7d}\033[m'  .format(n)
      s += ' \033[0;32m{:7d}\033[m'  .format(cnewf[k])
      s += ' \033[0;32m{:7.2f}\033[m'.format(avg_agef  [k])
      s += ' \033[0;32m{:7.2f}\033[m'.format(std_agef  [k])
      s += ' \033[0;32m{:7.2f}\033[m'.format(avg_pktlf [k])
      s += ' \033[0;32m{:7.2f}\033[m'.format(std_pktlf [k])
      s += ' \033[0;32m{:7.2f}\033[m'.format(avg_pktprf[k])
      s += ' \033[0;32m{:7.2f}\033[m'.format(std_pktprf[k])
      # s += ' \033[0;32m{:7.2f}\033[m'.format(avg_rpktcfage [k])
      # s += ' \033[0;32m{:7.2f}\033[m'.format(std_rpktcfage[k])
      print (s)

    return
