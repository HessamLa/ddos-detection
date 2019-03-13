class Stats:
    def __init__ (self, hashCode, p, labels_indices=[1,2,3,4,5,6,7,8]):
        self.newStat = True # True, if this stat has been modified then 
        self.newFlow = True # True, if this is created for a new flow entry

        #initialize labels
        self.iTime   = labels_indices [0]
        self.iSrcIp  = labels_indices [1] 
        self.iDstIp  = labels_indices [2]
        self.iProto  = labels_indices [3]
        self.iSrcPrt = labels_indices [4]
        self.iDstPrt = labels_indices [5]
        self.iTtl    = labels_indices [6]
        self.iFrameLen = labels_indices [7]

        self.flowHash = hashCode
        self.time   = p.ts  # records latest modifcation time of this Stat entry
        self.SrcIp  = p.sip
        self.DstIp  = p.dip
        self.Proto  = p.proto
        self.SrcPrt = p.sport
        self.DstPrt = p.dport
        self.Ttl    = p.ttl
        self.FrameLen = p.len
        self.pkt_cnt_total     = 0
        self.sum_pkt_len_total = 0

        self.pkt_cnt_win     = 0
        self.sum_pkt_len_win = 0
        self.pkt_len_avg_win = 0

        self.req_freq        = None # Request frequency
        self.req_phase_shift = None # Request phase shift
    
    def reinit_window (self):
        self.newStat = False
        self.newFlow = False
        self.pkt_cnt_win     = 0
        self.sum_pkt_len_win = 0
        self.pkt_len_avg_win = 0

    def analyze (self, p):
        self.newStat = True
        self.pkt_cnt_total += 1
        self.pkt_cnt_win += 1
        self.sum_pkt_len_win += p.len 
        self.sum_pkt_len_total += p.len
        self.time = p.ts

    def printInfo (self):
        print (self.newStat )
        print (self.newFlow )

        print (self.flowHash )
        print (self.SrcIp)
        print (self.DstIp  )
        print (self.Proto  )
        print (self.SrcPrt )
        print (self.DstPrt )
        print (self.pkt_cnt_total    )
        print (self.sum_pkt_len_total)

        print (self.pkt_cnt_win     )
        print (self.sum_pkt_len_win )
        print (self.pkt_len_avg_win )

        print (self.req_freq)
        print (self.req_phase_shift )
    
class ip_packet():
    def __init__ (self):
        self.ts    = 0
        self.sip   = 0x00000000
        self.dip   = 0x00000000
        self.proto = 0
        self.sport = 0
        self.dport = 0
        self.len   = 0
        self.ttl   = 0