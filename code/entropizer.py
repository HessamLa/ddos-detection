import numpy as np
from utilities import tlog
from utilities import COLOR_CODE as C
from entropyfunction import entropy
from utilities import getflowcat

def do_entropy(labels, data):
    # print ("do_entropy()")
    s = set(labels)
    print (len (s), "labels")
    if (len (s)==0):
        return None
    if (len (s)<200):
        n = []
        for l in s:
            indices = labels==l
            if (data.ndim==1):
                n.append ( data[indices].sum() )
            else:
                n.append ( data[indices].sum(axis=0) )
        # print ("Calculate entorpy")
        e = entropy (np.array (n))
    else:
        n = dict ()
        for i in range (len (labels)):
            l = labels[i]
            try:
                n[l] = n[l] + data[i]
            except:
                n[l] = data[i]
        # print ("Calculate entorpy")
        e = entropy (np.array (list (n.values())))
        
    return e

def entropize (ftbl):
    print (C.YLW, "\n*******ENTROPIZER*******", C.NC)
    print ("->  Make the table")
    tlog.start()
    sips, dips, sps, dps, proto, pcnt, plen, pstat = [], [], [], [], [], [], [], []
    for f in ftbl:
        if (f.dif_cnt == 0): # Don't include in active flows
            continue
        sips.append (f.sip)
        dips.append (f.dip)
        sps.append  (f.sport)
        dps.append  (f.dport)
        proto.append(f.proto)
        pcnt.append (f.dif_cnt)
        plen.append (f.dif_len)
        pstat.append ([f.dif_cnt, f.dif_len])

    sips = np.array (sips, dtype=int)
    dips = np.array (dips, dtype=int)
    sps  = np.array (sps, dtype=int)
    dps  = np.array (dps, dtype=int)
    proto= np.array (proto, dtype=int)
    pstat= np.array (pstat, dtype=int)
    pcnt = np.array (pcnt, dtype=int)
    plen = np.array (plen, dtype=int)

    print ("->  Flow cnt:", sips.shape)
    t_make_tbl = tlog.diff()
    
    tlog.start ()
    K=13
    # CAN THIS LINE BE MADE FASTER?
    pcnt_log10 = np.array ([getflowcat (f, cat_method=1, max_cat=K-1) for f in ftbl], dtype=int)
    # plen_log10 = np.array ([getflowcat (f, cat_method=3, max_cat=K-1) for f in ftbl], dtype=int)
    t_log10s = tlog.diff()

    for k in range (K):
        indices = pcnt_log10==k
        print ("->  k = ", k)
        e = do_entropy (sips[indices], pstat[indices])
        # print ("       SIP (%.2f, %.2f)"%(e[0],e[1]))
        e = do_entropy (dips[indices], pstat[indices])
        # print ("       DIP (%.2f, %.2f)"%(e[0],e[1]))
        e = do_entropy (sps[indices], pstat[indices])
        # print ("        SP (%.2f, %.2f)"%(e[0],e[1]))
        e = do_entropy (dps[indices], pstat[indices])
        # print ("        DP (%.2f, %.2f)"%(e[0],e[1]))
        e = do_entropy (proto[indices], pstat[indices])
        # print ("     PROTO (%.2f, %.2f)"%(e[0],e[1]))
    t_ent_set = tlog.diff()


    tlog.start ()
    e = do_entropy (sips, pstat)
    print ("       SIP (%.2f, %.2f)"%(e[0],e[1]))
    e = do_entropy (dips, pstat)
    print ("       DIP (%.2f, %.2f)"%(e[0],e[1]))
    e = do_entropy (sps, pstat)
    print ("        SP (%.2f, %.2f)"%(e[0],e[1]))
    e = do_entropy (dps, pstat)
    print ("        DP (%.2f, %.2f)"%(e[0],e[1]))
    e = do_entropy (proto, pstat)
    print ("     PROTO (%.2f, %.2f)"%(e[0],e[1]))
    e = do_entropy (pcnt_log10, pstat)
    print ("  PCNT_CAT (%.2f, %.2f)"%(e[0],e[1]))
    t_entropy_all  =tlog.diff()

    print (C.CYN,
    'entropize: tMake_table=%.2f\n'%(t_make_tbl),
    '           log10s=%.2f\n'%(t_log10s),
    '      entset =%.2f\n'%(t_ent_set),
    'getEntropies =%.2f\n'%(t_entropy_all), C.NC)