from structures import AssociativeEntry
from structures import AssociativeTable
from structures import ip_packet

from utilities import eprint
import numpy as np

import time


class EntropyEntry (AssociativeEntry):
    def __init__ (self, time, pkt_cnt=0, pkt_len=0):
        AssociativeEntry.__init__ (self, dirty=True, age=0)
        self.pkt_cnt = pkt_cnt # total number of packets
        self.pkt_len = pkt_len # total sum of packet sizes
        self.prv_cnt = 0       # previous number of packets
        self.prv_len = 0       # previous sum of packet sizes
        self.time = time
        return

    def reset (self):
        self.age += 1
        self.dirty = False
        self.prv_cnt = self.pkt_cnt
        self.prv_len = self.pkt_len
        return 

    def add (self, time, difPktCnt, difPktLen):
        self.age = 0
        self.time = time
        self.dirty = True            
        self.pkt_cnt += difPktCnt
        self.pkt_len += difPktLen
        return

    @property
    def dif_cnt (self):
        return self.pkt_cnt - self.prv_cnt

    @property
    def dif_len (self):
        return self.pkt_len - self.prv_len

class EntropyTable (AssociativeTable):
    def __init__ (self, id=0, name=None, entry_max_age=10):
        AssociativeTable.__init__ (self, id, name)
        self.max_age = entry_max_age # entries older than max_age can be removed
        self._entropy = []
        self.new_cnt = 0
        self.oldent_cnt = 0
        return

    def add (self, i, time, pkt_cnt=0, pkt_len=0):
        """add/update i-th entry"""
        if i not in self._tbl:
            self.new_cnt += 1
            self [i] = EntropyEntry (time, pkt_cnt, pkt_len)
        else:
            self [i].add (time, pkt_cnt, pkt_len)
        return

    @property
    def size (self):
        return len (self._tbl)

    def clear (self):
        self._tbl.clear()
        return
    
    def reset (self):
        self._entropy = []
        self.new_cnt = 0
        for ent in self:
            ent.reset ()
        return

    def remove_old (self):
        """Removes old entries"""
        for h in self._tbl:
            if (self._tbl[h].age > self.max_age ):
                self._tbl.pop (h)
        return

    @property
    def entropy (self):
        '''calculate entropy of each column in self._tbl, array of entropies
        '''
        if (len (self._entropy) != 0):
            return self._entropy

        # convert dictionary to numpy array
        if ( len (self._tbl) == 0 ):
            return np.array ([0,0])
        
        # t1 = time.time()
        array = np.array ([[ent.dif_cnt, ent.dif_len] for ent in self if ent.dirty==True], dtype='f')
        # t2 = time.time()
        p = array/array.sum (axis=0) # divide each cell by sum of its column
        if (len (p[p==0])>0):
            print ("ERROR WITH entropy()")
        p[p==0] = 1
        # logp = np.where(p>0, np.log(p), 0) # consider 0 for entries of p that are not positive
        # t3 = time.time()
        logp = np.log(p)
        # t4 = time.time()
        plogp = -np.multiply (p, logp)
        # t5 = time.time()
        # print ('%.2f %.2f %.2f %.2f '%(t2-t1, t3-t2, t4-t3, t5-t4))
        self._entropy = plogp.sum (axis=0) # sum over columns, and return a list of entries
        return self._entropy

    def printInfo (self):
        [ent_pcnt, ent_plen] = self.entropy
        print ('Table:{:6}|{:5}/{:5}      | ({:.2f}, {:.2f})'.format (self.name, self.new_cnt, len (self._tbl), ent_pcnt, ent_plen))
        # for t in self._tbl:
        #     print (t)

    def printEntries (self):
        for h in self.keys():
            print ("{:10}".format(str(h)), self[h].pkt_cnt, self[h].dif_cnt, self[h].pkt_len, self[h].dif_len)
