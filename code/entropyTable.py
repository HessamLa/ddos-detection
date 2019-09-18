from structures import AssociativeEntry
from structures import AssociativeTable
from structures import ip_packet

from utilities import eprint
import numpy as np

import time
from entropyfunction import entropy


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
    def __init__ (self, id=0, name=None, entry_min_time=10):
        AssociativeTable.__init__ (self, id, name)
        self.min_time = entry_min_time # entries older than min_time can be removed
        self.__entropy = []
        self.new_cnt = 0
        self.oldent_cnt = 0
        return

    def add (self, i, time, pkt_cnt=0, pkt_len=0):
        """add/update i-th entry"""
        # entry = self.tbl.setdefault (i, EntropyEntry (time, 0, 0))
        # entry.add (time, pkt_cnt, pkt_len)
        # return
        try:
            self.tbl [i].add (time, pkt_cnt, pkt_len)
        except KeyError:
            self.new_cnt += 1
            self.tbl [i] = EntropyEntry (time, pkt_cnt, pkt_len)
        return

        # if i not in self.tbl:
        #     self.new_cnt += 1
        #     self.tbl [i] = EntropyEntry (time, pkt_cnt, pkt_len)
        # else:
        #     self.tbl [i].add (time, pkt_cnt, pkt_len)
        # return

    def reset (self):
        self.__entropy = []
        self.new_cnt = 0
        for ent in self:
            ent.reset ()
        return

    def remove_old (self):
        """Removes old entries"""
        for h, f in self.tbl.items ():
            if (f.age > self.min_time ):
                self.tbl.pop (h)
        return

    @property
    def entropy (self):
        '''Calculates entropy of each column in the table
        Returns list-array of entropies
        '''
        if (len (self.__entropy) != 0):
            retval = self.__entropy

        # convert dictionary to numpy array
        elif ( self.size == 0 ):
            retval = np.array ([0,0])
        
        # t1 = time.time()
        else:
            array = np.array ([[ent.dif_cnt, ent.dif_len] for ent in self if ent.dirty==True], dtype='f')
            self.__entropy = entropy (array)
            retval = self.__entropy
        return retval.tolist()

    def printInfo (self):
        [ent_pcnt, ent_plen] = self.entropy
        print ('Table:{:6}|{:5}/{:5}      | ({:.2f}, {:.2f})'.format (self.name, self.new_cnt, self.size, ent_pcnt, ent_plen))
        # for t in self._tbl:
        #     print (t)

    def printEntries (self):
        for h, f in self.items():
            print ("{:10}".format(str(h)), f.pkt_cnt, f.dif_cnt, f.pkt_len, f.dif_len)
