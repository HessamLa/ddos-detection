import os
import sys
import csv

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
    def __init__ (self, labels_indices=[1,2,3,4,5,6], id=0, name=None):
        print 'New switch.  ID: {}   name: {}'.format (id, name)
        self.name = name
        self.id = id
        self.flows = dict()

        self.iTime   = labels_indices [0]
        self.iSrcIp  = labels_indices [1] 
        self.iDstIp  = labels_indices [2]
        self.iProto  = labels_indices [3]
        self.iSrcPrt = labels_indices [4]
        self.iDstPrt = labels_indices [5]
        self.iTtl    = labels_indices [6]
        self.iFrameLen = labels_indices [7]
        
        self.flow_ind = \
            [self.iSrcIp, self.iDstIp, self.iProto, self.iSrcPrt, self.iDstPrt, self.iTtl, self.iFrameLen]
        
        self.next_pkt_id = 0 # ID of the next immediate packet not processed so far. Note the first row of packets is for columns labels

        self.stats = dict()
    def update_properties (self, timewin=None):
        if timewin: self.timewin = timewin

    def send_packets (self, packets): # this method sends packets to the controller
        self.packets = packets
        self.process (packets)
        
    def get_stats (self):
        return self.stats

    def process (self, packets=None):
        # All previous stats must be marked as old
        for h in self.stats:
            self.stats [h].reinit_window()

        if packets == None:
            print 'No more packets left to process'
            return

        self.newflows = dict() # Initialize the newflows dictionary. If there is any new
        
        for p in packets:
            h = hash (str ([p[k] for k in self.flow_ind])) # Make a hash of packet
            if h in self.flows:
                self.flows [h].append (p)
            else:
                self.flows [h] = [p]
                self.newflows [h] = [p]
                self.stats [h] = Stats(h, p)
    
            self.stats [h].analyze (p)

def ipStr2Hex (ipStr):
    a = ipStr.split('.')
    return '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, a))

class Switch_Driver:
    switchCount = 0
    def __init__ (self, filename, dirpath='.', timewin=10.0):
        Switch_Driver.switchCount += 1

        self.filename=filename
        filepath = os.path.join(dirpath, filename)
        self.packets, labels_indices = \
            Parse_Csv (filepath)

        self.switch =  Switch_Class(labels_indices, id=Switch_Driver.switchCount, name=filename)

        self.iTime   = labels_indices [0]
        self.iSrcIp  = labels_indices [1] 
        self.iDstIp  = labels_indices [2]
        self.iProto  = labels_indices [3]
        self.iSrcPrt = labels_indices [4]
        self.iDstPrt = labels_indices [5]
        self.iTtl    = labels_indices [6]
        self.iFrameLen = labels_indices [7]
        
        self.next_pkt_id = 1 # 0th row of the file is expected to be column names
        self.timewin = float (timewin)
        self.time = sys.float_info.max
        if len (self.packets) > 1
            self.time    = float (self.packets [1][self.iTime]) # time of the first packet
        
    def adjustTime (self):
        if len (self.packets) > 1
            t = self.packets [1][self.iTime] # time of the first packet
        while self.time + self.timewin < t:
            self.time += self.timewin

    def finished (self):
        if self.next_pkt_id >= len(self.packets):
            return True
        return False

    def progress (self, timewin=None):
        if self.finished ():
            print 'No more packets left to progress:', self.filename
            return
        if timewin:
            self.timewin = float (timewin)

        i = self.next_pkt_id
        # print self.filename, 'continuing from time', t
        packets = []
        while i < len (self.packets) and (float (self.packets [i][self.iTime]) - self.time) < self.timewin:
            self.packets [i][self.iSrcIp]  = ipStr2Hex (self.packets [i][self.iSrcIp])
            self.packets [i][self.iDstIp]  = ipStr2Hex (self.packets [i][self.iDstIp])
            self.packets [i][self.iSrcPrt] = int (self.packets [i][self.iSrcPrt])
            self.packets [i][self.iDstPrt] = int (self.packets [i][self.iDstPrt])
            self.packets [i][self.iTtl]    = int (self.packets [i][self.iTtl])
            self.packets [i][self.iFrameLen] = int (self.packets [i][self.iFrameLen])

            # print 'xxx', i, self.filename, self.packets [i][self.iTime]
            packets.append (self.packets [i])
            i = i + 1
        self.switch.send_packets (packets=packets)
        # print '{} @{:.2f}   from {} to {}'. format (self.filename, t, self.next_pkt_id, i)
        self.next_pkt_id = i
        self.time += self.timewin


