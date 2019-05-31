#!/usr/bin/env py3
import getopt
import time
import numpy as np
import os
import sys
import matplotlib.pyplot as plt
import dpkt
import pickle # for srialization
from utilities import eprint
from structures import FTDObj
sys.path.append(".")

# import locals
import switch

class FlowTableDump:
    def __init__ (self, name, outdir):
        self.name = name

        print ("New FlowTableDump file    name:", name)
        self.filename = outdir+'/'+name+'.ftd' # Flow-Table Dump
        print (self.filename)
        self.f = open(self.filename, 'w+b')
        if (self.f == None):
            eprint ("ERR: Failed to open the file", self.filename)
            raise Exception
        return
    
    def dump_bin (self, flow_tbl):
        # eprint ("Dumping :", self.name)
        pickle.dump (flow_tbl, self.f)
        return
    
    def close_file (self):
        if (self.f != None):
            self.f.close()


class NetShot:
    def __init__ (self, pcapdir='.', nsdir='.', timewin=60.0, filterstr='', protocol=''): # protocol is a comma-separted list
        self.timewin = float(timewin) # SImulation time window in seconds. In each window, the packets will be analyzed
        self.protocols = protocol
        
        files = [f for f in os.listdir (pcapdir) if f.endswith ('pcap') and f.find (filterstr) != -1 ]        
        self.switches = dict ()
        self.netshots = dict ()

        times=[]
        for f in files: # FOREACH switch PCAP file, read the file and create corresponding objects
            # Create a switch object
            sd = switch.Switch_Driver (f, 'pcap', pcapdir, self.timewin, protocol)
            self.switches [f] = sd
            times.append (float (sd.time))

            # Create dumper object for each switch
            fd = FlowTableDump (os.path.splitext (f)[0], outdir=nsdir)
            self.netshots [f] = fd

        # readjust time of all switches to the earliest one
        basetime = int (min (times)/timewin)*timewin
        print ("Base Time:", basetime)
        for sd in self.switches:
            self.switches[sd].time = basetime

    def run(self):
        it = 0
        alldone = False
        while (not alldone):
            print ('Time: {:.2f} to {:.2f}'.format ( it*self.timewin, (it+1)*self.timewin))
            it += 1
            # all switches run
            for d in self.switches:
                sd = self.switches [d]
                sd.progress ()
                dumptype = FTDObj.DumpType.NO_FLOWTABLE_CHANGE
                for f in sd.switch.flow_table:
                    if f.dirty == True:
                        dumptype = FTDObj.DumpType.NEW_FLOWTABLE
                        break
                
                if dumptype == FTDObj.DumpType.NEW_FLOWTABLE:
                    obj = FTDObj.pack_obj (dumptype, sd.protocols, sd.timewin, sd.time, sd.switch.flow_table)
                elif dumptype == FTDObj.DumpType.NO_FLOWTABLE_CHANGE:
                    obj = FTDObj.pack_obj (dumptype, sd.protocols, sd.timewin, sd.time, None)
                
                self.netshots [d].dump_bin (obj)
            
            # if all switches are done getting new packets, then 
            alldone = True
            for d in self.switches:
                if self.switches[d].is_done == False:
                    alldone = False

        for d in self.netshots:
            self.netshots [d].close_file()

def parse_arguments (argv):
    # pcapdir = "/home/datasets/caida/ddos-20070804"
    home = os.path.expanduser("~")
    pcapdir = "/tmp/hessamla/" # input files
    pcapdir = home+"/ais-install-321/ns-3.28/pcap-output/" # input files
    nsdir = home+"/ddos-detection/captures_netshot" # output files
    nsdir = home+"/ddos-detection/captures_maccdc2012" # output files

    timewin = 60.0
    
    usage_msg = 'Usage: {} <inputfile> -o <csv-outputfile>'.format (argv[0])

    if (len (argv) <= 1):
        eprint ('WARN: No arguments are passed. Using default values.')
        eprint (usage_msg)

    try:
        opts, args = getopt.getopt(argv[1:],"hcd:t:o:",["help", "idir=", "timewin=", "odir"])
    except getopt.GetoptError:
        eprint ('ERR: Problem reading arguments.')
        eprint (usage_msg)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            eprint (usage_msg)
            eprint ("-h (--help)                   Prints this help")
            eprint ("-d (--idir) <pcap-directory>  Directory containing PCAP files")
            eprint ("-t (--timewin) <seconds>      Width of each time window in seconds")
            sys.exit()
        elif opt in ("-d", "--idir"):
            pcapdir = arg
        elif opt in ("-o", "--odir"):
            print (arg)
            nsdir = arg
        elif opt in ("-t", "--timewin"):
            timewin = float (arg)
    
    eprint ("")
    eprint ("*   Dir PCAPs =", pcapdir)
    eprint ("*Dir NetShots =", nsdir)
    eprint ("* Time Window =", timewin , 'seconds')
    eprint ("")

    return pcapdir, nsdir, timewin

if __name__ == "__main__":
    pcapdir, nsdir, timewin = parse_arguments (sys.argv)
    eprint ("Press anykey to coninue...")
    input()

    capture = NetShot (pcapdir=pcapdir,\
                     nsdir=nsdir,\
                     timewin=timewin,\
                     protocol={dpkt.ip.IP_PROTO_TCP,dpkt.ip.IP_PROTO_UDP,dpkt.ip.IP_PROTO_ICMP}\
        )
    capture.run()
    