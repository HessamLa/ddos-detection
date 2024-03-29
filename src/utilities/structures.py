from abc import abstractmethod
from enum import Enum
import copy
from src.utilities import eprint

class ip_packet():
    def __init__ (self):
        self.ts    = 0 # time-stamp; time of last modified
        self.tc    = 0 # time created; time of 
        self.sip   = 0x00000000
        self.dip   = 0x00000000
        self.proto = 0
        self.sport = 0
        self.dport = 0
        self.len   = 0
        self.ttl   = 0

class AssociativeEntry:
    def __init__ (self, key=None, dirty=None, age=0, ts=None):
        """The variables 'key' 'dirty' and 'time' will be included in each object
        if they are passed as an argument.
        Time is the last"""
        if (key != None):
            self.key=key
        if (dirty != None):
            self.dirty=dirty # Dirty flag. True, if this entry has been modified
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

    def __getitem__ (self, key):
        return self._tbl [key]

    def __setitem__ (self, key, value):
        self._tbl [key] = value
        return

    def __iter__ (self):
        for f in self._tbl.values():
            yield f

    def items (self):
        return self._tbl.items ()

    def values (self):
        return self._tbl.values ()
    
    def keys (self):
        """Returns keys for all entries"""
        return self._tbl.keys()

    def maketbl (self, tbl):
        """Shallow copies tbl into _tbl"""
        self._tbl = tbl.copy()
        return
        
    @property
    def tbl (self):
        """Returns the table"""
        return self._tbl

    @property
    def size (self):
        """Returns number of elements in this table"""
        return len (self._tbl)

    def copy (self):
        
        return 

    def clear (self):
        self._tbl.clear ()
        return
        
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

    @staticmethod
    def pack_obj (dumptype, protocols, timewin, time, flow_table):
        """ The input are dumptype, protocols, timewin, time, flow_table
        which pertain to a switch-driver
        returns obj = [dumptype, protocols, timewin, time, flow_table]
        """
        obj = [dumptype, protocols, timewin, time, flow_table]
        return obj
    @staticmethod
    def unpack_obj (obj):
        """ The input is an obj which pertain to a switch-driver state
        [protocols, timewin, time, flow_table] = obj
        return dumptype, protocols, timewin, time, flow_table
        """
        [dumptype, protocols, timewin, time, flow_table] = obj
        return dumptype, protocols, timewin, time, flow_table

