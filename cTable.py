import numpy as np
import itertools
from image_output import ImageOutput
from pcapstream import pickle_write

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
        self.sip = 1
        self.dip = 2 
        self.sp  = 3
        self.dp  = 4
        
        self.pw = None # Pickle Write, for saving entropies into file
        
        self.e_tbls = { # entropy tables
            self.sip: EntropyTable (id=self.sip, name='SrcIP'),  # Source IP table
            self.dip: EntropyTable (id=self.dip, name='DstIP'),  # Destination IP table
            self.sp : EntropyTable (id=self.sp,  name='SrcPrt'), # Source Port table
            self.dp : EntropyTable (id=self.dp,  name='DstPrt'), # Destination Port table
            }

        self.history = [] # list of entropies
        self.image_output = ImageOutput ()
        print ('New cTable created')
        return

    def __del__(self):
        if (self.pw):
            self.pw.close_file ()
        return

    def reinit (self):
        for t in self.e_tbls:
            self.e_tbls [t].clear()
    
    def aggregate_tables (self, tables, agg_table=None):
        """ tables is in the format of a dictionary of flow tables. This function, aggeregates flows in
        the format of entropy table. Only nelwy modifed entries will be taken into
        account.
        """
        if (agg_table==None):
            agg_table = { # Make a dictionary of EntropyTables, comprising of 4 entries.
                self.sip: EntropyTable (id=self.sip, name='SrcIP'), # Source IP table
                self.dip: EntropyTable (id=self.dip, name='DstIP'), # Destination IP table
                self.sp : EntropyTable (id=self.sp,  name='SrcPrt'), # Source Port table
                self.dp : EntropyTable (id=self.dp,  name='DstPrt'), # Destination Port table
                }
        for [name, flows] in tables:
            for h in flows.keys():
                if ( flows [h].dirty ): # get only the modified/new flows
                    pkt_cnt = flows [h].pkt_cnt
                    pkt_len = flows [h].pkt_len
                    if (pkt_cnt==0): eprint (name, "dif_cnt is zero XXXXXXXXXXXXXXXXXXXXXX") # REMOVE LATER
                    if (pkt_len==0): eprint (name, "dif_len is zero XXXXXXXXX743892 fhs uf")
                    agg_table[self.sip].add ( flows[h].sip,   pkt_cnt, pkt_len)
                    agg_table[self.dip].add ( flows[h].dip,   pkt_cnt, pkt_len)
                    agg_table[self.sp]. add ( flows[h].sport, pkt_cnt, pkt_len)
                    agg_table[self.dp]. add ( flows[h].dport, pkt_cnt, pkt_len)
        return agg_table

    def update_entropy_table (self, flows, agg_table=None):
        """ Make entropy table from the input flow table 'flows'"""
        if (agg_table==None):
            print ('MAKE NEW AGGREGATING TABLE')
            agg_table = { # Make a dictionary of EntropyTables, comprising of 4 entries.
                self.sip: EntropyTable (id=self.sip, name='SrcIP'), # Source IP table
                self.dip: EntropyTable (id=self.dip, name='DstIP'), # Destination IP table
                self.sp : EntropyTable (id=self.sp,  name='SrcPrt'), # Source Port table
                self.dp : EntropyTable (id=self.dp,  name='DstPrt'), # Destination Port table
                }
        for f in flows:
            if ( f.dirty ): # get only the modified/new flows
                dif_cnt = f.dif_cnt
                dif_len = f.dif_len
                ts = f.ts
                agg_table[self.sip].add ( f.sip,   ts, dif_cnt, dif_len)
                agg_table[self.dip].add ( f.dip,   ts, dif_cnt, dif_len)
                agg_table[self.sp]. add ( f.sport, ts, dif_cnt, dif_len)
                agg_table[self.dp]. add ( f.dport, ts, dif_cnt, dif_len)
        return agg_table    

    def update (self, ftable=None, data=None):
        # rest all tables
        for i in self.e_tbls:
            self.e_tbls [i].reset ()

        if ftable:
            self.e_tbls = self.update_entropy_table (ftable, self.e_tbls)
        
        self.saveEntropy (self.getEntropies(), 'entropies.dmp')

        if (len (self.history) > 20):
            self.history.pop(0)
        self.history.append ( self.getEntropies() )

    def getEntropies (self, tableId=None, tableName=None):
        """ If a specific tableId or tableName is requested, then return 1-D array of entropy.
        Otherwise, return all entropies in a dictionary.
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

    def saveEntropy (self, data, filename, outdir='.'):
        if (self.pw == None):
            self.pw = pickle_write (filename, outdir=outdir, mode='w+b')
        self.pw.dump (data)
        return

    def drawEntropy (self):
        # h = self.history[-1]
        # data = [] # will contain (name,value) tuples
        # for e in h:
        #     (id, name, entropy) = h[e]
            
        #     data.append ()
        
        self.image_output.draw (self.history[-1])

    def dumpEntropy (self, filename=None):
        if filename == None:
            filename = 'entropy.dmp'
        

        