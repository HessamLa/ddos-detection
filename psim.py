#!/usr/bin/env py3
import getopt
import time
import numpy as np
import os
import sys
import matplotlib.pyplot as plt
import dpkt
from utilities import eprint


sys.path.append(".")
# import locals
from controller import Controller
from switch import Switch_Driver
from cTable import cTable



class Simulator:
    def __init__ (self, idir='.', timewin=5.0, filterstr='', filetype='pcap', protocol=''): # protocol is a comma-separted list
        self.timewin = float(timewin) # SImulation time window in seconds. In each window, the packets will be analyzed

        files = [f for f in os.listdir (idir) if f.endswith (filetype) and f.find (filterstr) != -1 ]        
        self.switches = dict()
        self.controller = Controller ()
        self.ctable = cTable()
        
        self.protocols = protocol

        times=[]
        for f in files: # FOREACH switch-csv file, read the file and create corresponding switch obj
            # Make a switch object
            sd = Switch_Driver (f, filetype, idir, self.timewin, protocol)
            
            # for each switch-csv file make a switch
            self.switches [f] = sd
            times.append (float (sd.time))

            # Make one controller and introduce the switches to it
            self.controller.connect_switches ([sd.switch])
        
        # readjust time of all switches to the earliest one
        basetime = int (min (times)/timewin)*timewin
        self.current_sim_time = basetime
        print ("Base Time:", basetime)
        for sd in self.switches:
            self.switches[sd].time = basetime

    def run(self):
        it = 0
        alldone = False
        while (not alldone):
            self.current_sim_time += self.timewin
            print ('Time: {:.2f} to {:.2f}'.format ( it*self.timewin, (it+1)*self.timewin))
            it += 1
            # all switches run
            t1 = time.time()
            for d in self.switches:
                self.switches[d].progress ()
            # controller runs and collects stats from switches
            t2 = time.time()
            # self.controller.progress ()
            
            # get controller data and pass it to ctable
            # data = self.controller.get_data ()
            ftbl_all = self.controller.get_ftbl_all ()
            t3 = time.time()
            # self.ctable.reinit () # remove all data in this table
            # self.ctable.update (data=data)
            self.ctable.update (ftable=ftbl_all)
            t4 = time.time()
            print ('psim.run: tProgress=%.2f ftbl_all=%.2f cTable=%.2f'%(t2-t1,t3-t2, t4-t3))
            self.ctable.printInfo ()
            entropies = self.ctable.getEntropies ()
            self.ctable.drawEntropy ()

            # if all switches are done getting new packets, then 
            alldone = True
            for d in self.switches:
                if self.switches[d].is_done == False:
                    alldone = False

        # finalize
        # raw_input ("PRESS SOME KEY TO TERMINATE")
        eprint ("PRESS SOME KEY TO TERMINATE")
        # os.system("pause")

def parse_arguments (argv):
    inputdir = "pcap_small"
    inputdir = "pcap"
    inputdir = "ds-ns3"
    # inputdir = "/home/datasets/caida/ddos-20070804"
    inputdir = "/tmp/hessamla/"
    inputtype = "pcap"
    outputdir = "/home/hessamla/ddos-detection/captures_netshot/"

    inputdir = "/home/hessamla/ddos-detection/captures_netshot/"
    inputtype = "ftd" #Flow-Table Dump
    outputdir = ""

    timewin = 60
    
    usage_msg = 'Usage: {} -df <input-directory> -o <output-ftd-dirctory>'.format (argv[0])
    try:
        opts, args = getopt.getopt(argv[1:],"hcd:f:t:o:",["help", "pcapdir=", "ftddir", "timewin=", "odir"])
    except getopt.GetoptError:
        eprint ('ERR: Problem reading arguments.')
        eprint (usage_msg)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            eprint (usage_msg)
            eprint ("-h (--help)                   Prints this help")
            eprint ("-d (--pcapdir) <pcap-directory>  Directory containing PCAP files")
            eprint ("-f (--ftddir) <ftd-directory>   Directory containing Flow-Table Dump files")
            eprint ("-t (--timewin) <seconds>      Width of each time window in seconds")
            sys.exit()
        elif opt in ("-d", "--pcapdir"):
            inputdir = arg
            inputtype = "pcap"
        elif opt in ("-f", "--ftddir"):
            inputdir = arg
            inputtype = "ftd"
        elif opt in ("-o", "--odir"):
            outputdir = arg
        elif opt in ("-t", "--timewin"):
            timewin = float (arg)
    # if (len (args) > 0):
    #     inputfile = args[-1]
    else:
        eprint ('WARN: No arguments are passed. Using default values.')
    
    eprint ('Input Directory =', inputdir)
    eprint ('Input Type =', inputtype)
    eprint ('NetShot outputdir =', outputdir)
    eprint ('Time Window =', timewin , 'seconds')
    eprint ("")

    return inputdir, outputdir, inputtype, timewin

if __name__ == "__main__":
    # os.path.join(path, 'train-images-idx3-ubyte')
    # print (flow_ind)
    # print (iSrcIP, iDstIP, iProto, iSrcprt, iDstPrt)

    # filename = 'ais_ddos_switchPorts1-0-0.csv'
    # filepath = os.path.join('.', filename)
        
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
    idir, outputdir, inputtype, timewin = parse_arguments (sys.argv)

    print (idir, outputdir,inputtype, timewin)
    sim = Simulator (idir=idir, timewin=timewin,\
        filterstr='',\
        filetype=inputtype,\
        protocol={dpkt.ip.IP_PROTO_TCP,dpkt.ip.IP_PROTO_UDP,dpkt.ip.IP_PROTO_ICMP}\
        )
        # protocol={dpkt.ip.IP_PROTO_TCP,dpkt.ip.IP_PROTO_UDP})
    sim.run()
    # while (True):
    


    # print ([packets[1][i] for i in flow_ind])
    # print (str ([packets[1][iSrcIP], packets[1][iDstIP], packets[1][iProto], packets[1][iSrcprt], packets[1][iDstPrt]]))
    # print ( [ hash(str(packets[i])) for i in range (len(packets))])
    print ("Enter")
    input()
    
    
