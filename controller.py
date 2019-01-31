#from structures import *
#from switch import *
from cTable import *
from image_output import *

class Controller:
    def __init__ (self):
        self.switches = []
        self.stats = []
        self.data = []
        # self.ctable = cTable()

    def connect_switches (self, switches):
        self.switches = self.switches + switches

    def disconnect_switch (self, name):
        for s in self.switches:
            if s.name == name: self.switches.remove (s)

    def progress (self):
        # self.ctable.reinit () # remove all data in this table
        self.data = []
        for s in self.switches:
            self.data.append ([s.name, s.get_stats()])
            # self.ctable.update (s.name, s.get_stats())
        # self.ctable.printInfo ()
        # e = self.ctable.getEntropy ()
        # self.ctable.drawEntropy ()
        
    def get_data (self):
    # List of [switch.name, switch.get_stats()] pairs
        return self.data

    def process_table (self, table):
        print 'Processing table'

        
    def process_stats (self, data):
        print 'Processing stats'
        return
        for name, stats in data:
            print '[', name, ']'
            for h in stats:
                if stats [h].newFlow:
                    print 'new*', stats [h].pkt_cnt_total, stats [h].pkt_cnt_win
                elif stats [h].newStat:
                    print '    ', stats [h].pkt_cnt_total, stats [h].pkt_cnt_win
                else:
                    print 'all done'