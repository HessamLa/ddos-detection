import numpy as np
import itertools


import utilities as util
from utilities import eprint
from utilities.simulation_time import SimulationTime as STime
from datastructures.entropyTable import EntropyTable

import copy

# def entropy (a): # a in a numpy array
#     p = a/a.sum () # divide each cell by sum of its column
#     # plogp = -np.multiply (p, np.log (p))
#     logp = np.where(p>0, np.log(p), 0)
#     plogp = -np.multiply (p, logp)
#     return plogp.sum()


class EntropySet: # SHOULD USE A BETTER NAME FOR THIS CLASS
    def __init__ (self, ftbl=None, data=None, entrykeys=None):
        self.SIP = 1 # ENUMs
        self.DIP = 2 
        self.SP  = 3
        self.DP  = 4
        self.PROTO = 5
        self.PCNT  = 6
        self.PLEN  = 7
        
        self.pw = None # Pickle Write, for saving entropies into file
        
        self.e_tbls = self.__new_etables ()

        self.history = [] # list of entropies
        
        if (ftbl!=None or data!=None):
            self.update (ftbl=ftbl, data=data, entrykeys=entrykeys)
        return

    def __del__(self):
        if (self.pw):
            self.pw.close_file ()
        return

    def __new_etables (self):
        etbls = { # entropy tables
            self.SIP   : EntropyTable (id=self.SIP,    name='SrcIP'),  # Source IP table
            self.DIP   : EntropyTable (id=self.DIP,    name='DstIP'),  # Destination IP table
            self.SP    : EntropyTable (id=self.SP,     name='SrcPrt'), # Source Port table
            self.DP    : EntropyTable (id=self.DP,     name='DstPrt'), # Destination Port table
            self.PROTO : EntropyTable (id=self.PROTO,  name='Proto'),  # Transmission Protocol
            self.PCNT  : EntropyTable (id=self.PCNT,   name='PktCntCtgry'), # Packet Count
            }
        return etbls

    def reinit (self):
        for t in self.e_tbls:
            self.e_tbls [t].clear()

    def clear (self):
        self.e_tbls.clear()
    
    def aggregate_tables (self, tables, agg_table=None):
        """ tables is in the format of a dictionary of flow tables. This function, aggeregates flows in
        the format of entropy table. Only nelwy modifed entries will be taken into
        account.
        """
        if (agg_table==None):
            agg_table = self.__new_etables ()

        for [name, flows] in tables:
            for f in flows.values():
                pkt_cnt = f.pkt_cnt
                pkt_len = f.pkt_len
                agg_table[self.SIP].   add ( f.sip,   f.ts, pkt_cnt, pkt_len)
                agg_table[self.DIP].   add ( f.dip,   f.ts, pkt_cnt, pkt_len)
                agg_table[self.SP].    add ( f.sport, f.ts, pkt_cnt, pkt_len)
                agg_table[self.DP].    add ( f.dport, f.ts, pkt_cnt, pkt_len)
                agg_table[self.PROTO]. add ( f.proto, f.ts, pkt_cnt, pkt_len)
                cat_method=1
                agg_table[self.PCNT].  add ( util.getflowcat (f, cat_method), f.ts, pkt_cnt, pkt_len)
        return agg_table


    def update_entropy_table (self, flows, agg_table=None, entrykeys=None):
        """ Make entropy table from the input flow table 'flows'"""
        def add_entropy_entry (agg_table, f):
            dif_cnt = f.dif_cnt
            dif_len = f.dif_len
            agg_table[self.SIP].   add ( f.sip,   f.ts, dif_cnt, dif_len)
            agg_table[self.DIP].   add ( f.dip,   f.ts, dif_cnt, dif_len)
            agg_table[self.SP].    add ( f.sport, f.ts, dif_cnt, dif_len)
            agg_table[self.DP].    add ( f.dport, f.ts, dif_cnt, dif_len)
            agg_table[self.PROTO]. add ( f.proto, f.ts, dif_cnt, dif_len)
            cat_method=1
            agg_table[self.PCNT].  add ( util.getflowcat (f, cat_method), f.ts, dif_cnt, dif_len)

        if (agg_table==None):
            agg_table = self.__new_etables ()

        if (entrykeys != None):
            for h in entrykeys:
                f = flows [h]
                add_entropy_entry (agg_table, f)
        for f in flows:
            add_entropy_entry (agg_table, f)
            # dif_cnt = f.dif_cnt
            # dif_len = f.dif_len
            # ts = f.ts
            # agg_table[self.SIP].   add ( f.sip,   ts, dif_cnt, dif_len)
            # agg_table[self.DIP].   add ( f.dip,   ts, dif_cnt, dif_len)
            # agg_table[self.SP].    add ( f.sport, ts, dif_cnt, dif_len)
            # agg_table[self.DP].    add ( f.dport, ts, dif_cnt, dif_len)
            # agg_table[self.PROTO]. add ( f.proto, ts, dif_cnt, dif_len)
            # agg_table[self.PCNT].  add ( util.getflowcat (f, "log2pktcnt"), ts, dif_cnt, dif_len)
        return agg_table    

    def update (self, ftbl=None, data=None, entrykeys=None):
        # rest all tables
        for i in self.e_tbls:
            self.e_tbls [i].reset ()

        if ftbl:
            self.e_tbls = self.update_entropy_table (ftbl, self.e_tbls, entrykeys=entrykeys)
        

        if (len (self.history) > 20):
            self.history.pop(0)
        self.history.append ( self.getEntropies() )

    def getEntropies (self, tableId=None, tableName=None):
        """ If a specific tableId or tableName is requested, then return 1-D array of entropy.
        Otherwise, return all entropies in a dictionary.
        e [id] = (id, name, entropy);
        'id': table ID
        'name': table name
        'entropy': a two entry list [count_entropy, length_entropy]
        NOTE: The e_table must be reset() before obtaining the e_table.entropy.
        """

        if (tableId):
            for t in self.e_tbls:
                if self.e_tbls[t].id==tableId: return self.e_tbls[t].entropy
        elif (tableName):
            for t in self.e_tbls:
                if self.e_tbls[t].name==tableName: return self.e_tbls[t].entropy
        else:
            e = dict ()
            for t in self.e_tbls:
                e [ self.e_tbls[t].id] = (
                    self.e_tbls[t].id,
                    self.e_tbls[t].name,
                    self.e_tbls[t].entropy,
                    STime.nowtime,
                    STime.timewin
                    )
        return e

    def dumpEntropies (self, filename, mode='wb'):
        if (not hasattr(self, 'dumper')):
            self.dumper = util.pickle_write (filename, mode=mode)
        self.dumper.dump (self.getEntropies ())
        return
    
    def readEntropies (self, filename):
        # reader = util.pickle_read(filename)
        # e = reader.
        pass
    
    def printInfo (self):
        print ('EntropySet info:')
        print ('Table:Name  |new/total Entries|Entropy (cnt, len)')
        for etbl in self.e_tbls.values ():
            etbl.printInfo ()
            # self.e_tbls [t].printEntries ()
        print ('')

        

        