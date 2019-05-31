#!/usr/bin/env python3
#%%
import dpkt
import gzip
import sys
import glob
import ipaddress
import struct
import json as j
from structures import ip_packet
from utilities import eprint
from utilities import ipStr2Hex

import getopt
import pickle

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

SKIP_PACKET = -1

datalinks = {
    LINKTYPE_NULL     : ('NULL', None),
    LINKTYPE_ETHERNET : ('ETHERNET', 'handle_ethernet'),
    LINKTYPE_RAW      : ('RAW_IP', 'handle_ip'),
}
ATTRIBUTE = {'time', 'srcip', 'dstip', 'protocol', 'srcprt', 'dstprt', 'length'}

class ERR(Exception):
    NONE = 0
    OUT_OF_RANGE = 1
    NOT_SUPPORTED = 2
    CONVERSION = 3
    pass

def handle_ethernet (ts, pkt, obj):
    try:
        eth = dpkt.ethernet.Ethernet (pkt)
    except dpkt.dpkt.NeedData:
        pass
        return
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        return obj.process_ip (ts, eth.data)
    else:
        # Should I use a logger???
        # eprint ('ERR: Error unpacking a packet at %s. Packet is not IP type. Ignore and continue.'% (ts))
        return SKIP_PACKET

def handle_ip (ts, pkt, obj):
    try:
        ip = dpkt.ip.IP (pkt)
    except dpkt.dpkt.UnpackError:
        # Should I use a logger???
        # eprint ('ERR: Error unpacking a packet at %s. PCAP file is not IP type. Ignore and continue.'% (ts))
        return SKIP_PACKET
    return obj.process_ip (ts, ip)

class Parser (object):
    def __init__ (self, filename):
        self.x = 10
        self.last_ts = 0

        self.pkt_handler = None
        self.open_pcap (filename)

        self.cache_depth = 100000
        self.cache = [None for i in range (self.cache_depth)]
        self.cache_index = 0
        self.cache_cnt = 0
        return

    def open_pcap (self, filename):
        if filename [-3:] == '.gz':
            print >> sys.stderr, 'Opening compresse file: %s'%filename
            f = gzip.open (filename, 'rb')
        else:
            f = open (filename, 'rb')
        eprint ('PCAP Filename: ', filename)
        self.pcap = dpkt.pcap.Reader (f)
        self.__iter = iter(self)
        dlink = self.pcap.datalink()
        if dlink not in datalinks:
            eprint ("Datalink type: {:3d} Unknown".format (dlink) )
        else:
            eprint ("Datalink type: {:3d} {}".format (dlink, datalinks[dlink][0]))
            self.pkt_handler = globals()[datalinks [dlink][1]]
            # try:
                # self.pcap.dispatch (1, self.pkt_handler, self)
            # except dpkt.dpkt.NeedData:
                # pass
        return

    def process_ip (self, ts, ip):
        try:
            tsecond = int (ts)
        except ERR:
            eprint ('ERR: Timestamp conversion failure %s'%ts)
            return ERR.CONVERSION
            
        if type (ip) != dpkt.ip.IP:
            eprint ('ERR: Unknown IP type: %s'%type(ip))
            return ERR.NOT_SUPPORTED
        if ts < self.last_ts:
            eprint ('ERR: Mismatching time.')
            eprint ('     Packet time: %s'%ts)
            eprint ('     Last time:   %s'%self.last_ts)
        # print (tsecond, ip)
        
        p = ip_packet()
        p.ts  = ts
        p.sip = ipaddress.IPv4Address(ip.src)
        p.dip = ipaddress.IPv4Address(ip.dst)
        p.proto = ip.p
        # print (type (ip.data))
        if type (ip.data) in {dpkt.tcp.TCP, dpkt.udp.UDP}:
            # print (type (ip), ip.data.sport, ip.data.dport)
            p.sport = ip.data.sport # source port
            p.dport = ip.data.dport # destination port
        else:
            p.sport, p.dport = 0, 0
        p.ttl = ip.ttl
        p.len = ip.len
        return p

    def getnext (self, type='str'):
        funcname = 'get_%s'%type
        f = getattr(self, funcname)
        try:
            s = f(next(iter(self)))
        except StopIteration:
            s = None
            pass
        return s
        # return f(next(iter(self)))

    def getnext_pkt (self, count=1):
        try:
            p= next(iter(self))
        except StopIteration:
            p=None
            pass
        return p

    def get_str (self, p):
        if p == None:
            return None
        s = '{},{},{},{},{},{},{},{}'.format\
            (p.ts, p.sip, p.dip, p.proto, p.sport, p.dport, p.ttl, p.len)
        return s

    def get_json (self, p):
        if p == None:
            return None
        ts, ippkt = next (self)
        json = None
        return json

    def get_pkt (self, p):
        return p

    def printnext(self):
        s = self.getnext_str ()
        print (s)

    def geteach(self, type='str'):
        funcname = 'get_%s'%type
        f = getattr(self, funcname)
        for p in self:
            yield f (p)
    
    def geteach_str(self):
        for p in self:
            yield get_str (p)
    
    def geteach_pkt(self):
        for p in self:
            yield p

    def _fill_cache (self, count):
        self.cache_cnt = 0
        for ts, pkt in self.pcap:
            buf = self.pkt_handler (ts, pkt, self)
            if buf == None:
                return
            elif buf == SKIP_PACKET:
                continue
            else:
                self.cache[self.cache_cnt] = buf
                self.cache_cnt += 1
                if self.cache_cnt >= count:
                    return
        return

    def __iter__ (self):
        # ts, pkt = next(self.pcap)
        # while 1:

        # if (self.cache_index < len (self.cache)):
        #     yield self.cache [self.cache_index]
        #     self.cache_index += 1
        # else: # fill the cache
        #     self.fill_cache (self.cache_depth):
        
        for ts, pkt in self.pcap:
            buf = self.pkt_handler (ts, pkt, self)
            if buf == None:
                break
            elif buf == SKIP_PACKET:
                continue
            yield buf

    def __next__ (self):
        return next(iter(self))

class Test():
    def __init__(self):
        self.x = 10
        return
    
    def __iter__ (self):
        yield 1
def parse_arguments (argv):
    inputfile = None
    outputfile = None
    outformat = "str"

    usage_msg = 'Usage: {} <inputfile> -o <csv-outputfile>'.format (argv[0])
    try:
        opts, args = getopt.getopt(argv[1:],"ho:f:",["help", "ifile=", "ofile=", "oformat="])
    except getopt.GetoptError:
        eprint ('ERR: Problem reading arguments.')
        eprint (usage_msg)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            eprint (usage_msg)
            eprint ("-h (--help)             Prints this help")
            eprint ("-o (--ofile) <outfile>  Sends output to outfile")
            eprint ("--ifile <infile>        Explicitely sets the input file")
            eprint ("-f (--oformat) <type>   Sets the output format. Default is str. Available options are str, json, pkt.")
            sys.exit()
        elif opt in ("-o", "--ofile"):
            outputfile = arg
        elif opt in ("-f", "--oformat"):
            outformat = arg
        elif opt == "--ifile":
            inputfile = arg
    if (len (args) > 0):
        inputfile = args[-1]
    else:
        eprint ('WARN: No file is passed.')
        eprint (usage_msg)

    return inputfile, outputfile, outformat

#%%
if __name__ == "__main__":
    infile, outfile, outformat = parse_arguments (sys.argv)

    if (infile == None):
        infile = '/home/datasets/caida/ddos-20070804/ddostrace.20070804_134936.pcap'

    if (outformat == None):
        outformat = "str"

    eprint ('Input file is ', infile)
    eprint ('Output file is ', outfile)
    eprint ('Output format is ', outformat)

    p = Parser (infile)
    
    header='Time_Epoch,SrcIp,DstIp,Protocol,SrcPrt,DstPrt,TTL,FrameLen'
    
    if (outfile != None):
        with open(outfile, 'w') as file:  # Use file to refer to the file object
            file.write(header)
            for s in p.geteach(outformat):
                file.write(s+'\n')
    elif (outformat=='pkt'):
        out = sys.stdout.buffer
        for p in p.geteach_pkt():
            # out.write(p)
            print (p)
            d = pickle.dump (p)
            out.write(d)
            pickle.dump (p, sys.stdout.buffer)
        
    else:
        print (header)
        for s in p.geteach(outformat):
            print (s)
        
  

