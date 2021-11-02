#!/usr/bin/env python3

import os, sys
from pickle import NONE
from pathlib import Path
import time
import getopt
from typing import Protocol
import pandas as pd

import utilities as util

from utilities import eprint
from utilities import pickle_write, pickle_read
from utilities import COLOR_CODE as C
from datastructures.flowTable import FlowTable

from streamer import Streamer
sys.path.append(".")

class PCAP2FTD:
    """This class is used to generate partial flow-table data (ftd) files from PCAP files.
    The class works by taking all packets within a time window and crate the flow-table
    containing the partial flows in that time window, thus taking a shot of flows in a
    time window.
    """
    def __init__ (self, flowpkt_streamer, time_start=None, timewin=5.0, packet_filter=None, name="NoName"):
        """packet_filter is a function that verifies if a packet is OK (returns True) or should be skipped (returns False)
        """
        self.streamer = flowpkt_streamer
        self.flowtable = FlowTable(name=name)
        self.packetfilter = packet_filter

        self.total_pkt_counter=0
        self.accepted_pkt_counter=0
        if(time_start==None):
            self.p = self.streamer.getnext() # get time of the first packet
            self.tstart = (self.p.ts//timewin)*timewin # make time start divisible to 5
            self.flowtable.add_packet(self.p) # also don't waste this packet
            self.total_pkt_counter += 1
            self.accepted_pkt_counter+=1

        self.twin = float(timewin)
        self.tlimit = self.tstart + self.twin
    
    def __iter__ (self):
        for packet in self.streamer:
            self.total_pkt_counter += 1
            try:
                if(not self.packetfilter(packet)):
                    continue # skipp this packet
            except:
                pass

            if (packet.ts >= self.tlimit ):
                print(f"@timelimit {self.tlimit} total packets {self.total_pkt_counter}")
                ts_from = self.tlimit - self.twin
                ts_to = self.tlimit
                yield ts_from, ts_to, self.flowtable
                self.flowtable.clear()
                self.tlimit += self.twin
            
            self.flowtable.add_packet(packet)
            self.accepted_pkt_counter+=1
            

pcapdir="./datasets/cicddos2019/pcap"
ftddfdir="./"
timewin=1.0

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="FlowTable generator")
    
    parser.add_argument("pathsrc", type=str,
                help="Source path to the file or directory containing the PCAP files.")
    
    parser.add_argument("pathdst", type=str,
                help="Destination path to the file or directory where FTD pickles will be stored.")
    
    parser.add_argument("--typesrc", type=str, default="dir", choices=["dir", "file"],
                help="Type of the source path")
    
    parser.add_argument("--typedst", type=str, default="dir", choices=["dir", "file"],
                help="Type of the source path")
    
    parser.add_argument("--filename-pattern", type=str, default=None,
                help="A Unix filename pattern matching for filtering the list of input files. Those that don't match will be discarded."+
                    " ex. *.pcap or SAT*.pcap")
    
    parser.add_argument("--partition-size-KB", type=int, default=None,
                help="Partition FTD pickle files to into the given size in KB.")
    
    parser.add_argument("--ftd-basename", type=str, default="ftd",
                help="Base name for the destinatoin file. If type_dst is file, then this option is omited.")
    
    parser.add_argument("-t", "--timewin", type=float, default=5.0,
                help="Time window for each flowtable.")
    
    args = parser.parse_args()
    print(args)
    if  (args.typedst == "dir"):
        # Path(args.pathdst).mkdir(parents=True, exist_ok=True)
        ftdfilepath=f"{args.pathdst}/{args.ftd_basename}"
    elif(args.typedst == "file"):
        # Path(args.pathdst).parent.absolute().mkdir(parents=True, exist_ok=True)
        ftdfilepath=args.pathdst
    
    
    fnfilter=None
    if (args.filename_pattern):
        import fnmatch
        fnfilter=lambda x: fnmatch.fnmatch(x, args.filename_pattern)
    
    pwriter = pickle_write(ftdfilepath, partition_size=args.partition_size_KB*1024)
    streamer=Streamer.Make(source=args.pathsrc, source_type=args.typesrc, source_format="pcap",
                            buffersize=1, filenamefilter=fnfilter)
    streamer.summary()
    pcap_to_ftd = PCAP2FTD(streamer, timewin=args.timewin)
    for ts_from, ts_to, ftd in pcap_to_ftd:
        obj = (ts_from, ts_to, ftd)
        pwriter.dump(obj)

        # all_entries=[]
        # for hashkey, flowentry in ftd.tbl.items():
        #     v = flowentry
        #     E = [hashkey]
        #     E+= [v.ts, v.ts0, v.tc]
        #     E+= [v.saddr, v.daddr, v.proto, v.sport, v.dport]
        #     E+= [v.pktCnt, v.pktLen]
        #     all_entries += [E]
        # df = pd.DataFrame(all_entries, columns=["hashkey", "ts_latest","ts_previous", "ts_created", "saddr", "daddr", "proto", "sport", "dport", "pktcnt", "pktlen"])
        # print(df.head())
        # convert ftd to pandas
    pwriter.close()