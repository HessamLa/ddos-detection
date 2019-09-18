from flowTable import FlowTable
import math
from utilities import eprint
#from switch import *


class Controller:
    def __init__ (self):
        self.switches = []
        self.stats = []
        self.ftbl_all = FlowTable (id=0, name="Controller-All-Flows") # aggregated flows
        self.ftables = dict() # Dictionary of flow tables. Flow table of each switch can be referenced
                              # through this dictionary. Each switch is a key, and correponding flow table
                              # is the value
        
    def clear (self):
        self.ftbl_all.clear()
        self.ftables.clear()        
        return

    def connect_switches (self, switches):
        self.switches = self.switches + switches
            
    def disconnect_switch (self, name):
        for s in self.switches:
            if s.name == name: self.switches.remove (s)

    def add_ftable (self, ftbl):
        """Adds the passed flow table 'ftbl' to the aggregated flow table 'ftbl_all'"""
        for h, f in ftbl.items():                       # FOREACH flow entry
            if h not in self.ftbl_all.keys():      # IF the flow is dirty
                self.ftbl_all[h] = f.copy()
            else:
                self.ftbl_all[h].add (ts=f.ts, difCnt=f.dif_cnt, difLen=f.dif_len)
        return

    def aggregate_ftables (self):
        self.ftbl_all.reset ()

        # for s in self.switch_ftbl:
        #     ftbl = self.switch_ftbl[s]  # access the flow table of each switch
        for s in self.switches:
            ftbl = s.flow_table
            self.add_ftable (ftbl)
        return

    def progress (self):
        # # self.ctable.reinit () # remove all data in this table
        # self.data = []
        # for s in self.switches:
        #     self.data.append ([s.name, s.flow_table])
        
        # for s in self.switches:
        #     ftbl = s.flow_table

        self.aggregate_ftables ()
        return

    def get_data (self):
        self.data = []
        for s in self.switches:
            self.data.append ([s.name, s.flow_table])
        return self.data

    def get_ftbl (self, category='all'):
        """ returns a flow table pertaining to the given category. Categories include
        the following:
        'all' (default): all entries"""

        self.aggregate_ftables ()
        return self.ftbl_all

    def process_table (self, table):
        print ('Processing table')

        
    def process_stats (self, data):
        print ('Processing stats')
        return

        for name, stats in data:
            print ('[{}]'.format (name))
            for h in stats:
                if stats [h].newFlow:
                    print ('new*', stats [h].pkt_cnt_total, stats [h].pkt_cnt_win)
                elif stats [h].newStat:
                    print ('    ', stats [h].pkt_cnt_total, stats [h].pkt_cnt_win)
                else:
                    print ('all done')