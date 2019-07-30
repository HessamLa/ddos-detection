import subprocess
from utilities import eprint
from utilities import ipStr2Hex
from structures import ip_packet
from dpkt_pcap_parser import Parser
import pickle

class pickle_read:
    def __init__ (self, filepath):
        self.file = filepath
        mode='rb'
        self.f = open(filepath, mode)
        if (self.f is None):
            eprint ("ERR: Openning FTD file", filepath)
            eprint ("pickle_read.__init__()")
            exit()
        return
    def get_next (self):
        try:
            obj = pickle.load(self.f)
        except EOFError:
            eprint ("EOFError: Ran out of pickle input.") 
            eprint ("pickle_read.get_next()")
            return None
        return obj
    
    def objects (self):
        while (True):
            try:
                obj = pickle.load(self.f)
                yield obj
            except EOFError:
                eprint ("EOFError: Ran out of pickle input.") 
                eprint ("pickle_read.get_next()")
                return
    
    def close_file (self):
        if (self.f != None):
            self.f.close()
        return

class pickle_write:
    def __init__ (self, name, mode='w+b'):
        self.name = name
        self.filename = name
        try:
            self.f = open(self.filename, mode)
        except:
            eprint ("ERR: Failed to open/create the file", self.filename)
            eprint ("pickle_write.__init__()")
        return
    
    def dump (self, obj):
        # eprint ("Dumping :", self.name)
        try:
            pickle.dump (obj, self.f)
        except:
            eprint ("ERR: Problem dumping the pickle to", self.filename)
            eprint ("pickle_write.dump()")
            exit
        return
    
    def close_file (self):
        if (self.f != None):
            self.f.close()
        return

class dpkt_pcap2obj:
    def __init__ (self, pcapfilepath):
        self.parser = Parser (pcapfilepath)
        return
    def get_next_packet (self, count=1):
        # return self.parser.getnext('pkt')
        return self.parser.getnext_pkt (count)
        
class dpkt_pcap2pkt:
    def __init__ (self, pcapfilepath):
        outformat = '-f pkt '
        command='python3 dpkt_pcap_parser.py {} {}'.format (outformat, pcapfilepath)
        eprint ('PCAP streamer started. Command: ', command)
        self.p = subprocess.Popen(command\
            , shell=True\
            , stdout=subprocess.PIPE\
            #, stderr=subprocess.STDOUT\
            )
        return

    def get_next_packet (self):
        return self._get_next_pkt()

    def _get_next_pkt (self):
        p = pickle.load (self.p.stdout)
        print (p.ts)
        return p
        return self.p.stdout.readline()

class dpkt_pcap2csv:
    def __init__ (self, pcapfilepath):
        # args = ['python3 pcap_parser.py', pcapfilepath]
        outformat = '-f str '
        command='python3 dpkt_pcap_parser.py {} {}'.format (outformat, pcapfilepath)
        eprint ('PCAP streamer started. Command: ', command)
        self.p = subprocess.Popen(command\
            , shell=True\
            , stdout=subprocess.PIPE\
            #, stderr=subprocess.STDOUT\
            )

        self.labels_indices = None
        self.iSrcIp = None
        self.iDstIp = None
        self.iProto = None
        self.iSrcPrt = None
        self.iDstPrt = None
        self.iTime = None
        self.iTtl = None
        self.iFrameLen = None

        self.get_labels_indices()
        return

    def get_labels_indices (self): # This funcitons is meant to be called only once
        if (self.labels_indices):
            return self.labels_indices

        header = self.__get_next_line__().split(',')
        for i in range (len (header)):
            if   (header[i] == 'SrcIp'):      self.iSrcIp = i
            elif (header[i] == 'DstIp'):      self.iDstIp = i
            elif (header[i] == 'Protocol'):   self.iProto = i
            elif (header[i] == 'SrcPrt'):     self.iSrcPrt = i
            elif (header[i] == 'DstPrt'):     self.iDstPrt = i
            elif (header[i] == 'Time_Epoch'): self.iTime = i
            elif (header[i] == 'TTL'):        self.iTtl = i
            elif (header[i] == 'FrameLen'):   self.iFrameLen = i
        self.labels_indices = \
            [self.iTime, self.iSrcIp, self.iDstIp, self.iProto, self.iSrcPrt, self.iDstPrt, self.iTtl, self.iFrameLen]
        return self.labels_indices

    def get_next_packet (self):
        line = self.__get_next_line__ ()
        return self.__str_to_packet__ (line)

    def __str_to_packet__ (self, line):
        try:
            s = line.split (',')
        except:
            eprint ('ERR: Problem spliting the input line.')
            eprint ('     %s'%line)
            pass
            return None

        if (line==''):
            return None
        
        p = ip_packet()
        try:
            p.ts    = float (s [self.iTime])
            p.sip   = ipStr2Hex (s [self.iSrcIp])
            p.dip   = ipStr2Hex (s [self.iDstIp])
            p.sport = int (s [self.iSrcPrt])
            p.dport = int (s [self.iDstPrt])
            p.ttl   = int (s [self.iTtl])
            p.len   = int (s [self.iFrameLen])
            p.proto = int (s [self.iProto])
        except:
            eprint ('ERR: Problem converting the input line.')
            eprint ('     %s'%line)
            eprint ('     ', s)
            pass
            return None
        return p

    def __get_next_line__ (self):
        return self.p.stdout.readline().decode("utf-8").rstrip()
        # outs, _ = self.p.communicate(timeout=15)
        # eprint (outs.decode("utf-8").rstrip())
        # return outs.decode("utf-8").rstrip()

class TCPDump_Pcap2CSV:
    def __init__ (self, pcapfilepath, flags=""):
        if (flags==""):
            # flags =  "ip -nn --number --no-optimize -tt"
            flags =  "ip -nn -tt --number"

        command = "tcpdump {0} -r {1} 2>/dev/null".format (flags, pcapfilepath)
        self.p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.iTime   = 0
        self.iSrcIp  = 1
        self.iDstIp  = 2
        self.iProto  = 3
        self.iSrcPrt = 4
        self.iDstPrt = 5
        self.iTtl    = 6
        self.iFrameLen = 7
        self.labels_indices = \
            [self.iTime, self.iSrcIp, self.iDstIp, self.iProto, self.iSrcPrt, self.iDstPrt, self.iTtl, self.iFrameLen]
            # 0           1            2            3            4             5             6          7

    def get_labels_indices (self): # This funcitons is meant to be called only once
        return self.labels_indices

    def get_next_packet (self):
        line = self.p.stdout.readline().decode("utf-8") 
        p = [None]*8
        if (line==''):
            return None

        try:
            # l = str(line)
            l = line
            l = l.replace(">", "")
            l = l.replace(":", "")
            l = " ".join(l.split())
            l = l.split(' ')
            # l [0] Time field
            # l [2] SrcIP.Port
            # l [3] DdtIP.Port
            # l [4] Protocol
            # l [5] rest
            
            p[self.iTime] = float (l[1])
            if ( l[5].lower() == 'udp' or l[5].lower() == 'tcp' ): # If it is TCP or UDP protocol, Then get the port no.
                [ p[self.iSrcIp], p[self.iSrcPrt] ] = l[3].rsplit ('.', 1)
                [ p[self.iDstIp], p[self.iDstPrt] ] = l[4].rsplit ('.', 1)
                p[self.iSrcIp] = ipStr2Hex (p[self.iSrcIp])
                p[self.iDstIp] = ipStr2Hex (p[self.iDstIp])
                p[self.iSrcPrt] = int (p[self.iSrcPrt])
                p[self.iDstPrt] = int (p[self.iDstPrt])
            else:
                p[self.iSrcIp] = ipStr2Hex (l[3])
                p[self.iDstIp] = ipStr2Hex (l[4])
            p[self.iProto] = l[5]
            p[self.iFrameLen] = 0
            try:
                p[self.iFrameLen] = int (l[-1])
            except:
                p[self.iFrameLen] = 0
        except:
            eprint ("Exception occured")
            eprint ("Input line:{}".format(line))
            eprint ("Parsed:{}".format(p))
            raw_input("Press the <ENTER> key to continue...")
        return p

        # if (l==''):
            # return None
        # l = l.split (',')
        # l [self.iTime]   = float (l [self.iTime])
        # l [self.iSrcIp]  = ipStr2Hex (l [self.iSrcIp])
        # l [self.iDstIp]  = ipStr2Hex (l [self.iDstIp])
        # l [self.iTtl]    = int (l [self.iTtl])
        # l [self.iFrameLen] = int (l [self.iFrameLen])
        # if (self.iProto=='UDP' or self.iProto=='TCP'):
            # l [self.iSrcPrt] = int (l [self.iSrcPrt])
            # l [self.iDstPrt] = int (l [self.iDstPrt])
        # # print(l[0], l[self.iSrcIp], l[self.iTtl], l[self.iFrameLen], 'self.iFrameLen=', self.iFrameLen)
        # return l
    def get_next_packet_raw (self):
        return self.p.stdout.readline()
    
class TShark_Pcap2CSV:
    def __init__ (self, run_tshark, pcapfilepath):
        command="{} -h {}".format(run_tshark, pcapfilepath)
        self.p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        
        self.labels_indices = None
        self.iSrcIp = None
        self.iDstIp = None
        self.iProto = None
        self.iSrcPrt = None
        self.iDstPrt = None
        self.iTime = None
        self.iTtl = None
        self.iFrameLen = None

    def get_labels_indices (self): # This funcitons is meant to be called only once
        if (self.labels_indices):
            return self.labels_indices

        header = self.p.stdout.readline().split(',')
        for i in range (len (header)):
            if   (header[i] == 'SrcIp'):      self.iSrcIp = i
            elif (header[i] == 'DstIp'):      self.iDstIp = i
            elif (header[i] == 'Protocol'):   self.iProto = i
            elif (header[i] == 'SrcPrt'):     self.iSrcPrt = i
            elif (header[i] == 'DstPrt'):     self.iDstPrt = i
            elif (header[i] == 'Time_Epoch'): self.iTime = i
            elif (header[i] == 'TTL'):        self.iTtl = i
            elif (header[i] == 'FrameLen'):   self.iFrameLen = i
        self.labels_indices = \
            [self.iTime, self.iSrcIp, self.iDstIp, self.iProto, self.iSrcPrt, self.iDstPrt, self.iTtl, self.iFrameLen]
        return self.labels_indices

    def get_next_packet (self):
        l = self.p.stdout.readline()
        
        if (l==''):
            return None
        l = l.split (',')
        l [self.iTime]   = float (l [self.iTime])
        l [self.iSrcIp]  = ipStr2Hex (l [self.iSrcIp])
        l [self.iDstIp]  = ipStr2Hex (l [self.iDstIp])
        l [self.iTtl]    = int (l [self.iTtl])
        l [self.iFrameLen] = int (l [self.iFrameLen])
        if (self.iProto=='UDP' or self.iProto=='TCP'):
            l [self.iSrcPrt] = int (l [self.iSrcPrt])
            l [self.iDstPrt] = int (l [self.iDstPrt])
        # print(l[0], l[self.iSrcIp], l[self.iTtl], l[self.iFrameLen], 'self.iFrameLen=', self.iFrameLen)
        return l
    def get_next_packet_raw (self):
        return self.p.stdout.readline()
    
if __name__ == "__main__":
    flags =  "ip -nn --number --no-optimize -tt -l"
    filename = "/home/datasets/caida/ddos-20070804/ddostrace.20070804_141436.pcap"
    pcap_reader = TCPDump_Pcap2CSV (pcapfilepath=filename, flags=flags)
    l = 'x'
    while ( l != '' ):
        l = pcap_reader.get_next_packet ()
        # print l
