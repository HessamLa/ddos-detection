import os
import sys
import csv
import subprocess
import gc
import dpkt
from pcapstream import *
from dpkt_pcap_parser import Parser
import time

from structures import FTDObj

from utilities import eprint
from utilities import HashCollection

from flowTable import FlowEntry
from flowTable import FlowTable

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
        
        self.next_pkt_id = 0 # ID of the next immediate packet not processed so far. Note the first row of packets is for columns labels

        self._ftable = FlowTable (id=self.id, name=self.name)
        return

    def update_properties (self, timewin=None):
        if timewin: self.timewin = timewin
        return

    def send_packets (self, packets): # this method sends packets to the controller
        self.packets = packets
        self._process (packets)
        return

    @property
    def flow_table (self):
        # return self.__flows
        return self._ftable

    @flow_table.setter
    def flow_table (self, ftbl):
        # self.__flows = ftbl
        self._ftable = ftbl
        return

    def reinit (self):
        """Reset flags of all current entries
        """
        for flow in self._ftable:
            flow.reset ()
    
    def _process (self, packets=None):
        # # All previous stats must be marked as old
        # for h in self.stats:
        #     self.stats [h].reinit_window()

        if packets == None:
            eprint ('No more packets left to process')
            return

        for p in packets:
            # # print (p)
            # h = hash (str([p.sip, p.dip, p.proto, p.sport, p.dport])) # Make a hash of packet

            # if h not in self._ftable.keys():
            #     self._ftable [h] = FlowEntry(h, p)
            # else:
            #     self._ftable [h].add (ts=p.ts, difCnt=1, difLen=p.len)
            # OR WE COULD IMPLEMENT THIS:
            self._ftable.add_packet (p)

class Switch_Driver:
    switchCount = 0
    def __init__ (self, filename, filetype, dirpath='.', timewin=10.0, protocol_include=None): # protocol is a comma-separted list
        Switch_Driver.switchCount += 1

        self.protocols = None 
        if (protocol_include):
            self.protocols = protocol_include
        eprint ("Switch driver initiated. ID: ", Switch_Driver.switchCount,\
                "Protocols: ", self.protocols,
                "Source Type:", filetype)
        
        self.switch =  Switch_Class(id=Switch_Driver.switchCount, name=filename)

        self.filename=filename
        self.filetype=filetype
        filepath = os.path.join(dirpath, filename)
        # run_tshark='/home/hessamla/ddos-detection/pcap2csv/run-tshark'
        # self.pcap_reader = TShark_Pcap2CSV (run_tshark, filepath)
        # self.pcap_reader = TCPDump_Pcap2CSV (filepath, flags='')
        # self.pcap_reader = dpkt_pcap2csv (filepath)
        # self.pcap_reader = dpkt_pcap2pkt (filepath)
        self.timewin = float (timewin)
        self.time = 0.0

        if (self.filetype == 'pcap'):
            self.pcap_reader = dpkt_pcap2obj (filepath)
            
            self.p = self.pcap_reader.get_next_packet () # next packet to be processed in the system
            self.next_pkt_id = 1 # 0th row of the file is expected to be column names
            self.time = sys.float_info.max
            if (self.p):
                self.time = float (self.p.ts) # time of the first packet
        elif (self.filetype == 'ftd'):
            self.ftable_img_reader = pickle_read (filepath)

        self._done=False            
        # eprint ("{0} {1} {2}".format(self.filename, self.time, self.p))
        return

    @property
    def is_done (self):
        return self._done

    def progress (self, timewin=None):
        if (self._done == True):
            # eprint ('No more packets left to progress:', self.filename)
            return
        if timewin:
            self.timewin = float (timewin)
        
        self.switch.reinit()
        
            
        if (self.filetype == 'pcap'):
            # packets = self._read_pcaps()
            for packets in self._read_pcaps():
                self.switch.send_packets (packets=packets)
                # eprint ('{} @{:.2f}   from {} to {}'. format (self.filename, t, self.next_pkt_id, i))
                self.next_pkt_id += len (packets)
            self.time += self.timewin

        elif (self.filetype == 'ftd'):
            t1=time.time()
            dumptype, self.protocols, self.timewin, self.time, ftable = \
                self._read_ftable ()

            t2=time.time()
            # CAUTION:
            # self.switch.flow_table = ftable overwrites the flow table. It is faster and OK with
            # current requirements, which is only aiming at obtaining entropies and not modifying
            # the flow table entries. However, the right way to do it is to add ftable to the
            # existing flow table in the switch using the following which takes longer
            # self.switch.flow_table.add_table (ftable)
            if (dumptype==FTDObj.DumpType.NEW_FLOWTABLE): # update the flowtable if there is a change.
                self.switch.flow_table = ftable
                # self.switch.flow_table.add_table (ftable)

            t3=time.time()
            if (t3-t1 > 1):
                print ('switch.progress: tReadFTD=%.2f tAddTbl=%.2f'%(t2-t1, t3-t2))

        return

    def _read_pcaps (self):
        #  eprint (self.filename, 'continuing from time', t)
        packets=[]
        totalcnt = 0
        # t=-1 # COMMENT OUT
        # str = "{}".format(self.p .ts) # COMMENT OUT
        t0 = time.time()
        while (self.p and (self.p.ts - self.time) < self.timewin):
            if ( self.protocols==None ):    # If no protocol is given, then accept all packets
                packets.append (self.p)
            elif (self.p.proto in self.protocols): # Otherwise, accept only the recognized packets
                # print (self.protocols, self.p.proto, self.p.sport, self.p.dport)
                packets.append (self.p)
            # t = self.p.ts - self.time # COMMENT OUT
            self.p = self.pcap_reader.get_next_packet()
            if (len(packets) > 100000):
                totalcnt += len (packets)
                # print (totalcnt)
                
                yield packets
                packets = []
        if (self.p==None): self._done = True

        t1 = time.time()
        dif = t1-t0

        totalcnt += len (packets)
        if (totalcnt > 1):
            print (self.filename, "|Pkt Cnt:", totalcnt, '|exec time diff:', "{:.3f}".format(dif)) # COMMENT OUT
        if dif > 1:
            RED='\033[0;31m'
            NC='\033[0m' # No Color
            print (RED, '    Time elapsed:', dif, NC)
        
        yield packets
        return

    def _read_ftable (self):
        t1 = time.time()
        obj = self.ftable_img_reader.get_next ()
        t2 = time.time()
        # return FTDObj.unpack_obj (obj)
        dumptype, protocols, twin, t, flow_table = FTDObj.unpack_obj (obj)
        t3=time.time()
        print ("switch._read_ftabl: tReadFTD=%.2f tUnpack=%.2f"%(t2-t1, t3-t2))
        return dumptype, protocols, twin, t, flow_table

