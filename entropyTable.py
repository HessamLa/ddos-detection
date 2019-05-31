from structures import AssociativeEntry
from structures import AssociativeTable
from structures import ip_packet

from utilities import eprint
import numpy as np


class EntropyEntry (AssociativeEntry):
    def __init__ (self, pkt_cnt=0, pkt_len=0):
        AssociativeEntry.__init__ (self, dirty=True, age=0)
        self.pkt_cnt = pkt_cnt # total number of packets
        self.pkt_len = pkt_len # total sum of packet sizes
        self.prv_cnt = 0       # previous number of packets
        self.prv_len = 0       # previous sum of packet sizes
        return

    def reset (self):
        self.age += 1
        self.dirty = False
        self.prv_cnt = self.pkt_cnt
        self.prv_len = self.pkt_len
        return 

    def add (self, difPktCnt, difPktLen):
        self.age = 0
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
        print ('EntropyTable', name, self.__dict__.keys())
        return

    def add (self, i, pkt_cnt=0, pkt_len=0):
        """add/update i-th entry"""
        if i not in self._tbl:
            self [i] = EntropyEntry (pkt_cnt, pkt_len)
        else:
            self [i].add (pkt_cnt, pkt_len)
        return

    def elements_count (self):
        return len (self._tbl)

    def clear (self):
        self._tbl.clear()
        return
    
    def reset (self):
        for f in self:
            f.reset ()
        return

    def remove_old (self):
        """Removes old entries"""
        for h in self._tbl:
            if (self._tbl[h].age > self.max_age ):
                self._tbl.pop (h)
        return

    def entropy (self):
        '''calculate entropy of each column in self._tbl, array of entropies
        '''        
        # convert dictionary to numpy array
        if ( len (self._tbl) == 0 ):
            return np.array ([0,0])
        
        array = np.array ([[ent.dif_cnt, ent.dif_len] for ent in self if ent.dirty==True], dtype='f')
        p = array/array.sum (axis=0) # divide each cell by sum of its column
        # print (p[p<0])
        p[p==0] = 1
        # logp = np.where(p>0, np.log(p), 0) # consider 0 for entries of p that are not positive
        logp = np.log(p)
        plogp = -np.multiply (p, logp)
        return plogp.sum (axis=0) # sum over columns, and return a list of entries

    def printInfo (self):
        [ent_pcnt, ent_plen] = self.entropy ()
        print ('Table:{:6}|{:4} Entries| Entropy(cnt,len)=({:.2f}, {:.2f})'.format (self.name, len (self._tbl), ent_pcnt, ent_plen))
        # for t in self._tbl:
        #     print (t)
    def printEntries (self):
        for h in self.keys():
            print ("{:10}".format(str(h)), self[h].pkt_cnt, self[h].dif_cnt, self[h].pkt_len, self[h].dif_len)
