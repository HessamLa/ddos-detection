from flowTable import FlowTable
#from switch import *
from cTable import *
from image_output import *

class Controller:
    def __init__ (self):
        self.switches = []
        self.stats = []
        self.data = []
        self.flows_all = FlowTable (id=0, name="Controller-All-Flows")
        
    def connect_switches (self, switches):
        self.switches = self.switches + switches
            
    def disconnect_switch (self, name):
        for s in self.switches:
            if s.name == name: self.switches.remove (s)

    def aggregate_ftables (self):
        self.flows_all.reset ()

        # for s in self.switch_ftbl:
        #     ftbl = self.switch_ftbl[s]  # access the flow table of each switch
        for s in self.switches:
            ftbl = s.flow_table
            for h in ftbl.keys():                       # FOREACH flow entry
                if (ftbl[h].dirty == False): 
                    continue
                if h not in self.flows_all.keys():      # IF the flow is dirty
                    self.flows_all[h] = ftbl[h].copy()
                else:
                    self.flows_all[h].add (ts=ftbl[h].ts, difCnt=ftbl[h].dif_cnt, difLen=ftbl[h].dif_len)
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

    def get_ftbl_all (self):
        self.aggregate_ftables ()
        return self.flows_all

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