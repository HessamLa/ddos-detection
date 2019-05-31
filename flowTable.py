from structures import AssociativeEntry
from structures import AssociativeTable
from structures import ip_packet

from utilities import eprint

class FlowEntry (AssociativeEntry):
    def __init__ (self, hashCode, p):
        """This function, gets a packet
        hashCode is the signature of the flow. p is an ip_packet pertaining to the flow.
        """

        AssociativeEntry.__init__ (self, key=hashCode, dirty=True, age=0)
        self.new   = True # New Flow flag. True, if this is a new flow entry

        self.ts     = p.ts  # records latest modifcation time of this flow entry
        self.sip    = p.sip
        self.dip    = p.dip
        self.proto  = p.proto
        self.sport  = p.sport
        self.dport  = p.dport
        self.ttl    = p.ttl
        self.len    = p.len
        
        self.pkt_cnt = 1
        self.pkt_len = p.len

        self.prv_cnt = 0
        self.prv_len = 0

        self.req_freq        = None # Request frequency
        self.req_phase_shift = None # Request phase shift
    
    def reset (self):
        self.age += 1
        self.dirty = False
        self.new   = False

        self.prv_cnt = self.pkt_cnt
        self.prv_len = self.pkt_len
        return

    def add (self, ts, difCnt, difLen):
        """add the parameters of pkt or entry to an existing entry"""
        self.age = 0
        self.dirty = True

        self.ts     = ts
        self.pkt_cnt += difCnt
        self.pkt_len += difLen
        return

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

    # def keys_modified (self):
    #     """Returns keys for modified entries only"""

    def add_entry (self, p):
        h = hash (str([p.sip, p.dip, p.proto, p.sport, p.dport])) # Make a hash of packet
        
        if h not in self._tbl:
            self._tbl [h] = FlowEntry(h, p)
        else:
            self._tbl [h].add (p)
        return

    def remove_old (self):
        """Removes old entries"""
        for h in self._tbl:
            if (self._tbl[h].age > self.max_age ):
                self._tbl.pop (h)
        return
