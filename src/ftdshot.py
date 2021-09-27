#!/usr/bin/env python3

import getopt
import time
import numpy as np
import os
import sys
import matplotlib.pyplot as plt

import dpkt

import utilities as util
import datastructures

from utilities import eprint
from utilities import pickle_write
from utilities import COLOR_CODE as C
from datastructures.structures import FTDObj
from datastructures.flowTable import FlowTable

import switch

sys.path.append(".")

class FTDshot:
    """This class is used to generate partial flow-table data (ftd) files from PCAP files.
    The class works by taking all packets within a time window and crate the flow-table
    containing the partial flows in that time window, thus taking a shot of flows in a
    time window.
    """
    def __init__ (self, pcapdir='.', ftddir='.', timewin=60.0, filterstr='', protocol=''): # protocol is a comma-separted list
        self.timewin = float(timewin) # SImulation time window in seconds. In each window, the packets will be analyzed
        self.protocols = protocol
        
        files = [f for f in os.listdir (pcapdir) if f.endswith ('pcap') and f.find (filterstr) != -1 ]        
        self.switches = dict ()
        self.netshots = dict ()

        if (not os.path.exists(ftddir)):
            os.makedirs(ftddir)
            
        times=[]
        for f in files: # FOREACH switch PCAP file, read the file and create corresponding objects
            # Create a switch object
            sd = switch.Switch_Driver (f, 'pcap', pcapdir, self.timewin, protocol)
            self.switches [f] = sd
            times.append (float (sd.time))

            # Create dumper object for each switch
            # fd = pickle_write (os.path.splitext (f)[0]+'.ftd', outdir=ftddir)
            filename = ftddir+'/'+os.path.splitext (f)[0]+'.ftd'
            fd = pickle_write (filename, mode='w+b')
            self.netshots [f] = fd
            print ("")
        # readjust time of all switches to the earliest one
        basetime = int (min (times)/timewin)*timewin
        print ("Base Time:", basetime)
        for sd in self.switches:
            self.switches[sd].time = basetime

    def run(self):
        it = 0
        alldone = False
        while (not alldone):
            print (C.YLW+'Time: {:.2f} to {:.2f}\033[m'.format ( it*self.timewin, (it+1)*self.timewin))
            it += 1
            
            # Clear all flow tables before proceeding. This is because we need to boost
            # the processing speed, and also we only need to store flow table content
            # in each window
            for d in self.switches:
                self.switches [d].switch.flow_table.clear ()
            
            # all switches run
            for d in self.switches:
                sd = self.switches [d]
                sd.progress ()

                ftbl = sd.switch.flow_table
                if (ftbl.size != 0):
                    dumptype = FTDObj.DumpType.NEW_FLOWTABLE
                    print ("New Flow table %s. Store %d entries."%(sd.switch.name, ftbl.size))
                else:
                    dumptype = FTDObj.DumpType.NO_FLOWTABLE_CHANGE
                # for k in ftbl.keys():
                #     tmp[k] = ftbl[k].copy()
                # obj = FTDObj.pack_obj (dumptype, sd.protocols, sd.timewin, sd.time, tmp)
                obj = FTDObj.pack_obj (dumptype, sd.protocols, sd.timewin, sd.time, ftbl)
                self.netshots [d].dump (obj)
                #~Test ****************************************

            
            # if all switches are done getting new packets, then 
            alldone = True
            for d in self.switches:
                if self.switches[d].is_done == False:
                    alldone = False
            
            sys.stdout.flush()
            # END WHILE ##########################################

        for d in self.netshots:
            self.netshots [d].close_file()

def parse_arguments (argv):
    # pcapdir = "/home/datasets/caida/ddos-20070804"
    # home = os.path.expanduser("~")
    # pcapdir = "/tmp/hessamla/" # input files
    # pcapdir = home+"/ais-install-321/ns-3.28/pcap-output/" # input files
    # ftddir = home+"/ddos-detection/captures_netshot" # output files
    # ftddir = home+"/ddos-detection/captures_maccdc2012" # output files
    pcapdir = "."
    ftddir = "."

    timewin = 60.0
    
    usage_msg = 'Usage: {} <inputfile> -o <csv-outputfile>'.format (argv[0])

    if (len (argv) <= 1):
        eprint ('WARN: No arguments are passed. Using default values.')
        eprint (usage_msg)

    try:
        opts, args = getopt.getopt(argv[1:],"hcp:t:o:",["help", "idir=", "timewin=", "odir"])
    except getopt.GetoptError:
        eprint ('ERR: Problem reading arguments.')
        eprint (usage_msg)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            eprint (usage_msg)
            eprint ("-h (--help)                   Prints this help")
            eprint ("-p (--idir) <pcap-directory>  Directory containing PCAP files")
            eprint ("-o (--odir) <ftd-directory>   Output directory for flow-table data")
            eprint ("-t (--timewin) <seconds>      Width of each time window in seconds")
            sys.exit()
        elif opt in ("-p", "--idir"):
            pcapdir = arg
        elif opt in ("-o", "--odir"):
            print (arg)
            ftddir = arg
        elif opt in ("-t", "--timewin"):
            timewin = float (arg)
    
    eprint ("")
    eprint ("*   Dir PCAPs =", pcapdir)
    eprint ("*Dir NetShots =", ftddir)
    eprint ("* Time Window =", timewin , 'seconds')
    eprint ("")

    return pcapdir, ftddir, timewin

if __name__ == "__main__":
    pcapdir, ftddir, timewin = parse_arguments (sys.argv)
    # eprint ("Press anykey to coninue...")
    # input()

    capture = FTDshot (pcapdir=pcapdir,\
                     ftddir=ftddir,\
                     timewin=timewin,\
                     protocol={dpkt.ip.IP_PROTO_TCP,dpkt.ip.IP_PROTO_UDP,dpkt.ip.IP_PROTO_ICMP}\
        )
    capture.run()
    