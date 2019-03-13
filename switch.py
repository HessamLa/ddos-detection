import os
import sys
import csv
import subprocess
import gc
import dpkt
from pcapstream import *
from dpkt_pcap_parser import Parser
import time

from utilities import eprint

from structures import Stats

def Parse_Csv (filepath):
    def conv(s):
        try:
            s=float(s)
        except ValueError:
            pass    
        return s

    def read_csv (filepath):
        with open (filepath, 'r') as csvfile:
            packets = csv.reader(csvfile, delimiter=',')
            for p in packets:
                yield [ conv(i) for i in p ]

    packets = list (read_csv(filepath))


    # Get indices for each column label
    for i in range (len (packets[0])):
        if   (packets[0][i] == 'SrcIp'):      iSrcIp = i
        elif (packets[0][i] == 'DstIp'):      iDstIp = i
        elif (packets[0][i] == 'Protocol'):   iProto = i
        elif (packets[0][i] == 'SrcPrt'):     iSrcPrt = i
        elif (packets[0][i] == 'DstPrt'):     iDstPrt = i
        elif (packets[0][i] == 'Time_Epoch'): iTime = i
        elif (packets[0][i] == 'TTL'):        iTtl = i
        elif (packets[0][i] == 'FrameLen'):   iFrameLen = i

    return packets, [iTime, iSrcIp, iDstIp, iProto, iSrcPrt, iDstPrt, iTtl, iFrameLen]

class Switch_Class:
    def __init__ (self, id=0, name=None):
        eprint ('New switch Initiated.  ID: {}   name: {}'.format (id, name))
        self.name = name
        self.id = id

        self.flows = dict()
        
        self.next_pkt_id = 0 # ID of the next immediate packet not processed so far. Note the first row of packets is for columns labels

        self.stats = dict()

    def update_properties (self, timewin=None):
        if timewin: self.timewin = timewin

    def send_packets (self, packets): # this method sends packets to the controller
        self.packets = packets
        self.__process__ (packets)
        
    def get_stats (self):
        return self.stats

    def reinit (self):
        # Remove all stat entries
        self.stats.clear ()
        self.flows.clear ()
    
    def __process__ (self, packets=None):
        # # All previous stats must be marked as old
        # for h in self.stats:
        #     self.stats [h].reinit_window()

        if packets == None:
            eprint ('No more packets left to process')
            return

        self.newflows = dict() # Initialize the newflows dictionary. If there is any new
        
        for p in packets:
            # print (p)
            h = hash (str([p.sip, p.dip, p.proto, p.sport, p.dport])) # Make a hash of packet
            if h in self.flows:
                self.flows [h].append (p)
            else:
                self.flows [h] = [p]
                self.newflows [h] = [p]
                self.stats [h] = Stats(h, p)
    
            self.stats [h].analyze (p)
        
        # for h in self.stats:
        #     if (not self.stats [h].newStat): # remove old stat entries
        #         self.stats.pop (h, None)

class Switch_Driver:
    switchCount = 0
    def __init__ (self, filename, dirpath='.', timewin=10.0, protocol_include=None): # protocol is a comma-separted list
        Switch_Driver.switchCount += 1

        self.protocols = None 
        if (protocol_include):
            self.protocols = protocol_include
        eprint ("Switch driver initiated. ID: ", Switch_Driver.switchCount,\
                "Protocols: ", self.protocols)
        self.switch =  Switch_Class(id=Switch_Driver.switchCount, name=filename)

        self.filename=filename
        filepath = os.path.join(dirpath, filename)
        # run_tshark='/home/hessamla/ddos-detection/pcap2csv/run-tshark'
        # self.pcap_reader = TShark_Pcap2CSV (run_tshark, filepath)
        # self.pcap_reader = TCPDump_Pcap2CSV (filepath, flags='')
        # self.pcap_reader = dpkt_pcap2csv (filepath)
        # self.pcap_reader = dpkt_pcap2pkt (filepath)
        self.pcap_reader = dpkt_pcap2obj (filepath)
        

        self.p = self.pcap_reader.get_next_packet () # next packet to be processed in the system
        self.next_pkt_id = 1 # 0th row of the file is expected to be column names
        self.timewin = float (timewin)
        self.time = sys.float_info.max
        if (self.p):
            self.time = float (self.p.ts) # time of the first packet
        
        # eprint ("{0} {1} {2}".format(self.filename, self.time, self.p))

    def adjustTime (self):
        if (self.p):
            t = self.p.ts # time of the first packet
        while self.time + self.timewin < t:
            self.time += self.timewin

    def finished (self):
        if self.p==None:
            return True
        else:
            return False

    def progress (self, timewin=None):
        if (self.p == None):
            # eprint ('No more packets left to progress:', self.filename)
            return
        if timewin:
            self.timewin = float (timewin)
        self.switch.reinit()
        
        #  eprint (self.filename, 'continuing from time', t)
        packets=[]
        t=-1 # COMMENT OUT
        packetscount=0
        # str = "{}".format(self.p .ts) # COMMENT OUT
        t0 = time.time()
        while (self.p and (self.p .ts - self.time) < self.timewin):
            if ( self.protocols==None ):    # If no protocol is given, then accept all packets
                packets.append (self.p)
            elif (self.p.proto in self.protocols): # Otherwise, accept only the recognized packets
                # print (self.protocols, self.p.proto, self.p.sport, self.p.dport)
                packets.append (self.p)
            t = self.p.ts - self.time # COMMENT OUT
            self.p = self.pcap_reader.get_next_packet()
            
            # if (None and len (packets) >= 100000):  # If number of packets is too much, send this batch to the switch and restart
            #     self.switch.send_packets (packets=packets)
            #     packetscount += len (packets)
            #     packets = []
        t1 = time.time()
        dif = t1-t0

        packetscount += len (packets)
        eprint (self.filename, "|Pkt Cnt:", len(packets), '|time diff:', "{:.3f}".format(t)) # COMMENT OUT
        if dif > 1:
            RED='\033[0;31m'
            NC='\033[0m' # No Color
            eprint (RED, '    Time elapsed:', dif, NC)

        self.switch.send_packets (packets=packets)
        # eprint ('{} @{:.2f}   from {} to {}'. format (self.filename, t, self.next_pkt_id, i))
        self.next_pkt_id += packetscount
        self.time += self.timewin
