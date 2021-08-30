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
FINISHED = -2

datalinks = {
    LINKTYPE_NULL     : ('NULL', None),
    LINKTYPE_ETHERNET : ('ETHERNET', 'handle_ethernet'),
    LINKTYPE_RAW      : ('RAW_IP', 'handle_ip'),
}
ATTRIBUTE = {'time', 'srcip', 'dstip', 'protocol', 'srcprt', 'dstprt', 'length'}
ETH_TYPES = {dpkt.ethernet.ETH_TYPE_EDP,\
            dpkt.ethernet.ETH_TYPE_PUP,\
            dpkt.ethernet.ETH_TYPE_IP,\
            dpkt.ethernet.ETH_TYPE_ARP,\
            dpkt.ethernet.ETH_TYPE_AOE,\
            dpkt.ethernet.ETH_TYPE_CDP,\
            dpkt.ethernet.ETH_TYPE_DTP,\
            dpkt.ethernet.ETH_TYPE_REVARP,\
            dpkt.ethernet.ETH_TYPE_8021Q,\
            dpkt.ethernet.ETH_TYPE_8021AD,\
            dpkt.ethernet.ETH_TYPE_QINQ1,\
            dpkt.ethernet.ETH_TYPE_QINQ2,\
            dpkt.ethernet.ETH_TYPE_IPX,\
            dpkt.ethernet.ETH_TYPE_IP6,\
            dpkt.ethernet.ETH_TYPE_PPP,\
            dpkt.ethernet.ETH_TYPE_MPLS,\
            dpkt.ethernet.ETH_TYPE_MPLS_MCAST,\
            dpkt.ethernet.ETH_TYPE_PPPoE_DISC,\
            dpkt.ethernet.ETH_TYPE_PPPoE,\
            dpkt.ethernet.ETH_TYPE_LLDP,\
            dpkt.ethernet.ETH_TYPE_TEB
            }

def handle_ethernet (ts, pkt, obj):
    try:
        eth = dpkt.ethernet.Ethernet (pkt)
    except dpkt.dpkt.NeedData:
        pass
        return
    # if eth.type == dpkt.ethernet.ETH_TYPE_IP:
    #     Counter.ip += 1
    # elif eth.type == dpkt.ethernet.ETH_TYPE_8021Q:
    #     Counter.vlan += 1
    # else:
    if eth.type not in ETH_TYPES:
        # Should I use a logger???
        eprint ('ERR: Error unpacking a packet at %s. Packet is %s type.\nIgnore and continue.'%\
            (ts, eth.type))
        return SKIP_PACKET, None
    return obj.process_ip (ts, eth.data), eth.type

def handle_ip (ts, pkt, obj):
    try:
        ip = dpkt.ip.IP (pkt)
    except dpkt.dpkt.UnpackError:
        # Should I use a logger???
        eprint ('ERR: Error unpacking a packet at %s. Packet is %s type.\nIgnore and continue.'%\
            (ts, type(ip)))
        return SKIP_PACKET, None
    return obj.process_ip (ts, ip), type(dpkt.ip.IP)

class ERR(Exception):
    NONE = 0
    OUT_OF_RANGE = 1
    NOT_SUPPORTED = 2
    CONVERSION = 3
    pass

class PacketCounter:
    ip = 0
    vlan = 0
    def __init__ (self):
        self._all = 0 # total number of packets
        self._EDP          = 0
        self._PUP          = 0
        self._IP           = 0
        self._ARP          = 0
        self._AOE          = 0
        self._CDP          = 0
        self._DTP          = 0
        self._REVARP       = 0
        self._8021Q        = 0
        self._8021AD       = 0
        self._QINQ1        = 0
        self._QINQ2        = 0
        self._IPX          = 0
        self._IP6          = 0
        self._PPP          = 0
        self._MPLS         = 0
        self._MPLS_MCAST   = 0
        self._PPPoE_DISC   = 0
        self._PPPoE        = 0
        self._LLDP         = 0
        self._TEB          = 0
        return

    @property
    def all (self):
        return self._all

    def count (self, typ):
        self._all += 1
        if typ == dpkt.ethernet.ETH_TYPE_EDP:
            self._EDP += 1
        elif typ == dpkt.ethernet.ETH_TYPE_PUP:
            self._PUP += 1
        elif typ == dpkt.ethernet.ETH_TYPE_IP:
            self._IP += 1
        elif typ == dpkt.ethernet.ETH_TYPE_ARP:
            self._ARP += 1
        elif typ == dpkt.ethernet.ETH_TYPE_AOE:
            self._AOE += 1
        elif typ == dpkt.ethernet.ETH_TYPE_CDP:
            self._CDP += 1
        elif typ == dpkt.ethernet.ETH_TYPE_DTP:
            self._DTP += 1
        elif typ == dpkt.ethernet.ETH_TYPE_REVARP:
            self._REVARP += 1
        elif typ == dpkt.ethernet.ETH_TYPE_8021Q:
            self._8021Q += 1
        elif typ == dpkt.ethernet.ETH_TYPE_8021AD:
            self._8021AD += 1
        elif typ == dpkt.ethernet.ETH_TYPE_QINQ1:
            self._QINQ1 += 1
        elif typ == dpkt.ethernet.ETH_TYPE_QINQ2:
            self._QINQ2 += 1
        elif typ == dpkt.ethernet.ETH_TYPE_IPX:
            self._IPX += 1
        elif typ == dpkt.ethernet.ETH_TYPE_IP6:
            self._IP6 += 1
        elif typ == dpkt.ethernet.ETH_TYPE_PPP:
            self._PPP += 1
        elif typ == dpkt.ethernet.ETH_TYPE_MPLS:
            self._MPLS += 1
        elif typ == dpkt.ethernet.ETH_TYPE_MPLS_MCAST:
            self._MPLS_MCAST += 1
        elif typ == dpkt.ethernet.ETH_TYPE_PPPoE_DISC:
            self._PPPoE_DISC += 1
        elif typ == dpkt.ethernet.ETH_TYPE_PPPoE:
            self._PPPoE += 1
        elif typ == dpkt.ethernet.ETH_TYPE_LLDP:
            self._LLDP += 1
        elif typ == dpkt.ethernet.ETH_TYPE_TEB:
            self._TEB += 1
        return
    
    @staticmethod
    def total ():
        return Counter.ip + Counter.vlan
    

class Parser (object):
    def __init__ (self, filename):
        self.x = 10
        self.last_ts = 0
        self.filename = filename

        self.pkt_handler = None

        # This cache works as a queue
        self.cache_depth = 100000
        self.cache = [None for i in range (self.cache_depth)]
        self.cache_index = 0
        self.cache_cnt = 0
        
        # This member is used for counting packets based on their types
        self.counter = PacketCounter ()

        self._open_pcap ()
        return

    def _open_pcap (self):
        fname = self.filename
        if fname [-3:] == '.gz':
            print >> sys.stderr, 'Opening compressed file: %s'%fname
            f = gzip.open (fname, 'rb')
        else:
            f = open (fname, 'rb')
        eprint ('PCAP Filename: ', fname)
        self.pcap = dpkt.pcap.Reader (f)
        # self._iter = iter(self)
        dlink = self.pcap.datalink()
        if dlink not in datalinks:
            eprint ("Datalink type: {:3d} Unknown".format (dlink) )
        else:
            eprint ("Datalink type: {:3d} {}".format (dlink, datalinks[dlink][0]))
            self.pkt_handler = globals()[datalinks [dlink][1]]

        return

    def process_ip (self, ts, ip):
        try:
            tsecond = int (ts)
        except ERR:
            eprint ('ERR: Timestamp conversion failure %s'%ts)
            eprint ('File', self.filename, "Packet# =", self.counter.all)
            exit ()
            return 
            
        # if type (ip) != dpkt.ip.IP:
        if not isinstance (ip, dpkt.ip.IP):
            eprint ('ERR: Unknown IP type: %s'%type(ip), "Packet# =", self.counter.all)
            # print ("process_ip(): Counts: vlan=%d ip=%d"%(Counter.vlan, Counter.ip))
            # exit()
            return SKIP_PACKET
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


    # def getnext_pkt (self, count=1):
    #     if self.cache_index == self.cache_cnt:
    #         ret = self._fill_cache(count=100000)
    #         if ret==0:
    #             return None
        
    #     p = self.cache [self.cache_index]
    #     self.cache_index += 1
    #     return p


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
            yield self.get_str (p)
    
    def geteach_pkt(self):
        for p in self:
            yield p

    def getnext_pkt (self, count=1):
        try:
            p= next(self)
            # print ("getnext_pkt", p)
        except StopIteration:
            p=None
            pass
        return p

    def _fill_cache (self, count=0):
        import time
        t1 = time.time()
        if count==0:
            count=self.cache_depth
        self.cache_index=0
        self.cache_cnt=0
        for ts, pkt in self.pcap:
            buf, pktype = self.pkt_handler (ts, pkt, self)
            # print ("_fill_cache", buf.ts)
            if buf == None:
                break
            elif buf != SKIP_PACKET:
                self.counter.count (pktype) # this is only for counting packets
                self.cache[self.cache_cnt] = buf
                self.cache_cnt += 1
                if self.cache_cnt == count:
                    break
            else: # if buf == SKIP_PACKET:
                continue

            # if (buf):
            #     self.cache[self.cache_cnt] = buf
            #     self.cache_cnt += 1
            #     if self.cache_cnt >= count:
            #         break
            # elif buf == SKIP_PACKET:
            #     continue
            # else: # if buf == None:
            #     break

        t2 = time.time()
        # print ("_fill_cache() count=%d time=%.2f"%(self.cache_cnt, t2-t1))
        return self.cache_cnt

    def __iter__ (self):
        return self
        # for ts, pkt in self.pcap:
        #     buf = self.pkt_handler (ts, pkt, self)
        #     if buf == None:
        #         break
        #     elif buf == SKIP_PACKET:
        #         continue
        #     yield buf

    def __next__ (self):
        # return next(iter(self))
        
        if self.cache_index == self.cache_cnt:
            ret = self._fill_cache()
            if ret==0:
                raise StopIteration
        
        p = self.cache [self.cache_index]
        self.cache_index += 1
        return p

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
        
  

