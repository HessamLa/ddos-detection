import numpy as np
from image_output import ImageOutput

def entropy (a): # a in a numpy array
    p = a/a.sum () # divide each cell by sum of its column
    # plogp = -np.multiply (p, np.log (p))
    logp = np.where(p>0, np.log(p), 0)
    plogp = -np.multiply (p, logp)
    return plogp.sum()

class tableEntry:
    def __init__ (self, pkt_cnt=0, pkt_len=0):
        self.pkt_cnt = pkt_cnt # total number of packets
        self.pkt_len = pkt_len # total sum of packet sizes

    def add (self, pktCnt, pktLen):
        self.pkt_cnt += pktCnt
        self.pkt_len += pktLen

class entropyTable:
    def __init__ (self, id=0, name=None):
        self.id = id
        self.name = name
        self.tbl = dict ()

    def __setitem__(self, i, data):
        self.tbl [i] = tableEntry ()

    def __getitem__ (self, i):
        return self.tbl [i]
    
    def update (self, i, pkt_cnt=0, pkt_len=0):
        if i not in self.tbl:
            self.tbl [i] = tableEntry (pkt_cnt, pkt_len)
        else:
            self.tbl [i].add (pkt_cnt, pkt_len)

    def clear (self):
        self.tbl.clear()
    
    def entropy (self): # calculate entropy of each column in self.tbl, array of entropies
        # convert dictionary to numpy array
        array=np.array([[val.pkt_cnt, val.pkt_len] for (key,val) in self.tbl.iteritems()], dtype='f')
        
        p = array/array.sum (axis=0) # divide each cell by sum of its column
        # plogp = -np.multiply (p, np.log (p))
        logp = np.where(p>0, np.log(p), 0)
        plogp = -np.multiply (p, logp)
        return plogp.sum (axis=0)

    def printInfo (self):
        print 'Table: {:12}. {:4} Entries. Entropy={}'.format (self.name, len (self.tbl), self.entropy ())

class cTable:
    def __init__ (self):
        self.sip = 1
        self.dip = 2 
        self.sp  = 3
        self.dp  = 4
        
        self.table = {
            self.sip: entropyTable (id=self.sip, name='SrcIP'), # Source IP table
            self.dip: entropyTable (id=self.dip, name='DstIP'), # Destination IP table
            self.sp : entropyTable (id=self.sp,  name='SrcPrt'), # Source Port table
            self.dp : entropyTable (id=self.dp,  name='DstPrt'), # Destination Port table
            }
        self.history = [] # list of entropies
        self.image_output = ImageOutput ()
        print 'New cTable created'

    def reinit (self):
        for t in self.table:
            self.table [t].clear()
    
    def update (self, switch_name=None, stats=None, data=None):
        if switch_name and stats:
            for s in stats:
                pkt_cnt = stats [s].pkt_cnt_win
                pkt_len = stats [s].sum_pkt_len_win

                self.table[self.sip].update ( hash (stats[s].SrcIp), pkt_cnt, pkt_len)
                self.table[self.dip].update ( hash (stats[s].DstIp), pkt_cnt, pkt_len)
                self.table[self.sp]. update ( stats[s].SrcPrt, pkt_cnt, pkt_len)
                self.table[self.dp]. update ( stats[s].SrcPrt, pkt_cnt, pkt_len)
        elif data:
            for [name, stats] in data:
                for s in stats:
                    pkt_cnt = stats [s].pkt_cnt_win
                    pkt_len = stats [s].sum_pkt_len_win

                    self.table[self.sip].update ( hash (stats[s].SrcIp), pkt_cnt, pkt_len)
                    self.table[self.dip].update ( hash (stats[s].DstIp), pkt_cnt, pkt_len)
                    self.table[self.sp]. update ( stats[s].SrcPrt, pkt_cnt, pkt_len)
                    self.table[self.dp]. update ( stats[s].SrcPrt, pkt_cnt, pkt_len)

        self.history.append ( self.getEntropy() )

    def getEntropy (self, tableId=0, tableName=None):
        # If a specific tableId or tableName is requested, then return 1-D array of entropy.
        # Otherwise, return all entropies in a dictionary.
        if (tableId):
            for t in self.table:
                if self.table[t].id==tableId: e = self.table[t].entropy()
        elif (tableName):
            for t in self.table:
                if self.table[t].name==tableName: e = self.table[t].entropy()
        else:
            # Each entropy dictionay entry is as follows:
            # | tableId | tableName | [entropies numpy array] |
            e = dict ()
            for t in self.table:
                e [self.table[t].id] = (
                    self.table[t].id,
                    self.table[t].name,
                    self.table[t].entropy()
                    )
        return e
        
    def printInfo (self):
        print 'cTable info:'
        for t in self.table:
            self.table [t].printInfo ()
        print ''

    def drawEntropy (self):
        self.image_output.draw (self.history)
        