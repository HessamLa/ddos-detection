from structures import AssociativeEntry
from structures import AssociativeTable
from structures import ip_packet

from utilities import eprint
import math

class FlowEntry (AssociativeEntry):
  def __init__ (self, hashCode, p):
    """This function, gets a packet
    hashCode is the signature of the flow. p is an ip_packet pertaining to the flow.
    """

    AssociativeEntry.__init__ (self, key=hashCode, dirty=True)
    self.new   = True # New Flow flag. True, if this is a new flow entry

    self.ts   = p.ts  # time-stamp, records latest modifcation time of this flow entry
    self.ts0  = p.ts  # time-stamp, records previous modification time 
    self.tc   = p.ts  # time created, records time of creating this flow entry. Once set, this variable shall not be modified
    self.sip  = p.sip
    self.dip  = p.dip
    self.proto  = p.proto
    self.sport  = p.sport
    self.dport  = p.dport
    self.ttl  = p.ttl
    self.len  = p.len
    
    self.pkt_cnt = 1
    self.pkt_len = p.len

    self.prv_cnt = 0
    self.prv_len = 0

    self.req_freq    = None # Request frequency
    self.req_phase_shift = None # Request phase shift
  
  def reset (self):
    self.dirty = False
    self.new   = False

    self.prv_cnt = self.pkt_cnt
    self.prv_len = self.pkt_len
    return

  def add (self, ts, difCnt, difLen):
    """add the parameters of pkt or entry to an existing entry"""
    self.dirty = True

    self.ts0  = self.ts
    self.ts   = ts
    self.pkt_cnt += difCnt
    self.pkt_len += difLen
    return

  @property
  def age (self):
    """Returns age of this flow: timestamp of latest packet - time of flow creating in flow table
    """
    return self.ts - self.tc

  @property
  def dif_cnt (self):
    return self.pkt_cnt - self.prv_cnt

  @property
  def dif_len (self):
    return self.pkt_len - self.prv_len

  def printInfo (self):
    print ("key:", self.key)
    print ("dirty:", self.dirty)
    
    print ("is new:", self.new)
    print ("sip dip proto sport dport:",\
      self.sip, self.dip, self.proto, self.sport, self.dport)
    print ("pkt_cnt pkt_len:", self.pkt_cnt, self.pkt_len)


class FlowTable (AssociativeTable):
  def __init__ (self, id=0, name=None, entry_max_age=10):
    AssociativeTable.__init__ (self, id, name)
    self.max_age = entry_max_age # entries older than max_age can be removed
    return

  def add_packet (self, p):
    """Adds the packet p to the flow table. Returns key of the corresponding entry"""
    h = hash (str([p.sip, p.dip, p.proto, p.sport, p.dport])) # Make a hash of packet
    try:
      self.tbl [h].add (p.ts, 1, p.len)
    except KeyError:
      self.tbl [h] = FlowEntry(h, p)
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

    for h in t.keys():
      try:
        self.tbl[h].add (t[h].ts, t[h].dif_cnt, t[h].dif_len)
      except KeyError:
        self.tbl[h] = t[h].copy()
    return

    #   if h not in self.keys():
    #     self[h] = t[h].copy()
    #   else:
    #     self[h].add (t[h].ts, t[h].dif_cnt, t[h].dif_len)
    # return
  
  def remove_entry (self, h):
    try:
      del self.tbl[h]
    except KeyError:
      eprint ("ERR: Could not remove entry %s from the table %s." % (self.name))
      pass
    return

  # def remove_old (self):
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
