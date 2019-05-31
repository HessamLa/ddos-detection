from abc import abstractmethod
from enum import Enum
from utilities import eprint
import copy

class ip_packet():
    def __init__ (self):
        self.ts    = 0
        self.sip   = 0x00000000
        self.dip   = 0x00000000
        self.proto = 0
        self.sport = 0
        self.dport = 0
        self.len   = 0
        self.ttl   = 0

class AssociativeEntry:
    def __init__ (self, key=None, dirty=None, age=None):
        """The variables 'key' 'dirty' and 'age' will be included in each object
        if they are passed as an argument"""
        if (key != None):
            self.key=key
        if (dirty != None):
            self.dirty=dirty # Dirty flag. True, if this entry has been modified
        if (age != None):
            self.age=age
        return

    @abstractmethod
    def reset (self):
        pass

    def copy (self):
        return copy.copy (self)
    
class AssociativeTable:
    def __init__ (self, id=0, name=None):
        self.id=id
        self.name = name
        self._tbl = dict ()
        return

    def __getitem__ (self, h):
        return self._tbl [h]

    def __setitem__ (self, h, entry):
        self._tbl [h] = entry
        return

    def __iter__ (self):
        for h in self._tbl:
            yield self._tbl[h]

    def keys (self):
        """Returns keys for all entries"""
        return self._tbl.keys()

    def reset (self):
        """Reset flag of every flow in this table."""
        for f in self:
            f.reset ()
        return

class FTDObj: # Flow Table Dump Obj
    def __init__ (self):
        return
    class DumpType (Enum):
        NEW_FLOWTABLE=1
        NO_FLOWTABLE_CHANGE=2
        NONE=3

    @classmethod
    def pack_obj (cls, dumptype, protocols, timewin, time, flow_table):
        """ The input are protocols, timewin, time, flow_table which
        pertain to a switch-driver
        returns obj = [protocols, timewin, time, flow_table]
        """
        obj = [dumptype, protocols, timewin, time, flow_table]
        return obj
    @classmethod
    def unpack_obj (cls, obj):
        """ The input is an obj which pertain to a switch-driver state
        [protocols, timewin, time, flow_table] = obj
        return protocols, timewin, time, flow_table
        """

        [dumptype, protocols, timewin, time, flow_table] = obj
        return dumptype, protocols, timewin, time, flow_table

