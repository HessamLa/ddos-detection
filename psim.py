#!/usr/bin/env py3
import time
import numpy as np
import os
import sys
import matplotlib.pyplot as plt
import dpkt


sys.path.append(".")
# import locals
from controller import Controller
from switch import Switch_Driver
from cTable import cTable



class Simulator:
    def __init__ (self, dirpath='.', timewin=5.0, filter='switch', protocol=''): # protocol is a comma-separted list
        self.timewin = float(timewin) # SImulation time window in seconds. In each window, the packets will be analyzed

        files = [f for f in os.listdir (dirpath) if f.endswith ('pcap') and f.find (filter) != -1 ]
        self.switches = dict()
        self.controller = Controller ()
        self.ctable = cTable()
        
        self.protocols = protocol

        times=[]
        for f in files: # FOREACH switch-csv file, read the file and create corresponding switch obj
            # Make a switch object
            sd = Switch_Driver (f, dirpath, self.timewin, protocol)
            
            # for each switch-csv file make a switch
            self.switches [f] = sd
            times.append (float (sd.time))

            # Make one controller and introduce the switches to it
            self.controller.connect_switches ([sd.switch])
        
        # readjust time of all switches to the earliest one
        for sd in self.switches:
            self.switches[sd].time = min (times)

    def run(self):
        it = 0
        alldone = False
        while (not alldone):
            print ('Time: {:.2f} to {:.2f}'.format ( it*self.timewin, (it+1)*self.timewin))
            it += 1
            # all switches run
            for d in self.switches:
                self.switches[d].progress ()
            # controller runs and collects stats from switches
            self.controller.progress ()
            
            # get controller data and pass it to ctable
            self.ctable.reinit () # remove all data in this table
            data = self.controller.get_data ()
            self.ctable.update (data=data)
            self.ctable.printInfo ()
            self.ctable.drawEntropy ()

            # if all switches are done getting new packets, then 
            alldone = True
            for d in self.switches:
                if self.switches[d].finished () == False:
                    alldone = False

        # finalize
        # raw_input ("PRESS SOME KEY TO TERMINATE")
        # print ("PRESS SOME KEY TO TERMINATE")
        # os.system("pause")

        

if __name__ == "__main__":
    # os.path.join(path, 'train-images-idx3-ubyte')
    # print (flow_ind)
    # print (iSrcIP, iDstIP, iProto, iSrcprt, iDstPrt)

    filename = 'ais_ddos_switchPorts1-0-0.csv'
    filepath = os.path.join('.', filename)
        
    # sw = Switch_Class (filepath)
    # sw.analyze()
    # sw.analyze()
    # sw.analyze()
    # sw.analyze()

    # pcap_reader = TCPDump_Pcap2CSV ("/home/datasets/caida/ddos-20070804/ddostrace.20070804_141936.pcap")
    # l = '1'
    # while ( l != '' ):
        # l = pcap_reader.get_next_packet()
        # print (l)
    # exit()

    dirpath = "pcap_small"
    dirpath = "pcap"
    dirpath = "ds-ns3"
    # dirpath = "/home/datasets/caida/ddos-20070804"
    sim = Simulator (dirpath=dirpath, timewin=10, filter='',\
        protocol={dpkt.ip.IP_PROTO_TCP,dpkt.ip.IP_PROTO_UDP,dpkt.ip.IP_PROTO_ICMP})
        # protocol={dpkt.ip.IP_PROTO_TCP,dpkt.ip.IP_PROTO_UDP})
    sim.run()
    # while (True):
    


    # print ([packets[1][i] for i in flow_ind])
    # print (str ([packets[1][iSrcIP], packets[1][iDstIP], packets[1][iProto], packets[1][iSrcprt], packets[1][iDstPrt]]))
    # print ( [ hash(str(packets[i])) for i in range (len(packets))])
