import numpy as np
import itertools

from entropyTable import EntropyTable

from utilities import eprint
from utilities import HashCollection
import copy

def entropy (a): # a in a numpy array
    p = a/a.sum () # divide each cell by sum of its column
    # plogp = -np.multiply (p, np.log (p))
    logp = np.where(p>0, np.log(p), 0)
    plogp = -np.multiply (p, logp)
    return plogp.sum()


class cTable: # SHOULD USE A BETTER NAME FOR THIS CLASS
    def __init__ (self):
        self.SIP = 1 # ENUMs
        self.DIP = 2 
        self.SP  = 3
        self.DP  = 4
        self.PROTO = 5
        
        self.pw = None # Pickle Write, for saving entropies into file
        
        self.e_tbls = self._new_etables ()

        self.history = [] # list of entropies
        
        print ('New cTable created')
        return

    def __del__(self):
        if (self.pw):
            self.pw.close_file ()
        return

    def _new_etables (self):
        etbls = { # entropy tables
            self.SIP   : EntropyTable (id=self.SIP,    name='SrcIP'),  # Source IP table
            self.DIP   : EntropyTable (id=self.DIP,    name='DstIP'),  # Destination IP table
            self.SP    : EntropyTable (id=self.SP,     name='SrcPrt'), # Source Port table
            self.DP    : EntropyTable (id=self.DP,     name='DstPrt'), # Destination Port table
            self.PROTO : EntropyTable (id=self.PROTO,  name='Proto'),  # Transmission Protocol
            }
        return etbls

    def reinit (self):
        for t in self.e_tbls:
            self.e_tbls [t].clear()

    def clear (self):
        self.e_table.clear()
    
    def aggregate_tables (self, tables, agg_table=None):
        """ tables is in the format of a dictionary of flow tables. This function, aggeregates flows in
        the format of entropy table. Only nelwy modifed entries will be taken into
        account.
        """
        if (agg_table==None):
            agg_table = self._new_etables ()

        for [name, flows] in tables:
            for h in flows.keys():
                pkt_cnt = flows [h].pkt_cnt
                pkt_len = flows [h].pkt_len
                agg_table[self.SIP].   add ( flows[h].sip,   pkt_cnt, pkt_len)
                agg_table[self.DIP].   add ( flows[h].dip,   pkt_cnt, pkt_len)
                agg_table[self.SP].    add ( flows[h].sport, pkt_cnt, pkt_len)
                agg_table[self.DP].    add ( flows[h].dport, pkt_cnt, pkt_len)
                agg_table[self.PROTO]. add ( flows[h].proto, pkt_cnt, pkt_len)
        return agg_table

    def update_entropy_table (self, flows, agg_table=None):
        """ Make entropy table from the input flow table 'flows'"""
        if (agg_table==None):
            print ('MAKE NEW AGGREGATION TABLE')
            agg_table = self._new_etables ()

        for f in flows:
            if ( f.dirty ): # get only the modified/new flows
                dif_cnt = f.dif_cnt
                dif_len = f.dif_len
                ts = f.ts
                agg_table[self.SIP].   add ( f.sip,   ts, dif_cnt, dif_len)
                agg_table[self.DIP].   add ( f.dip,   ts, dif_cnt, dif_len)
                agg_table[self.SP].    add ( f.sport, ts, dif_cnt, dif_len)
                agg_table[self.DP].    add ( f.dport, ts, dif_cnt, dif_len)
                agg_table[self.PROTO]. add ( f.proto, ts, dif_cnt, dif_len)
        return agg_table    

    def update (self, ftable=None, data=None):
        # rest all tables
        for i in self.e_tbls:
            self.e_tbls [i].reset ()

        if ftable:
            self.e_tbls = self.update_entropy_table (ftable, self.e_tbls)
        

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
                if self.e_tbls[t].id==tableId: e = self.e_tbls[t].entropy
        elif (tableName):
            for t in self.e_tbls:
                if self.e_tbls[t].name==tableName: e = self.e_tbls[t].entropy
        else:
            e = dict ()
            for t in self.e_tbls:
                e [ self.e_tbls[t].id] = (
                    self.e_tbls[t].id,
                    self.e_tbls[t].name,
                    self.e_tbls[t].entropy
                    )
        return e
        
    def printInfo (self):
        print ('cTable info:')
        print ('Table:Name  |new/total Entries|Entropy (cnt, len)')
        for t in self.e_tbls:
            self.e_tbls[t].printInfo ()
            # self.e_tbls [t].printEntries ()
        print ('')

        

        