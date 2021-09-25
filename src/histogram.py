import numpy as np
import math

class Histogram:
    def __init__ (self, id=0, name='', max_size=None, bin_width=100, data=None):
        """max_size and bin_width must be defined.
        """
        self.id=id
        self.name=name
        self.__w = bin_width

        self.__max_size=max_size # maximum payload size
        self.__bins = [i*self.__w for i in range (math.ceil (self.__max_size/self.__w)+1)]
        if (data != None):
            self.makeHistogram (data)
        return

    @property
    def hist (self):
        return self.__hist

    def makeHistogram (self, data):
        self.__hist, _ = np.histogram (data, self.__bins, density=False)
    
    def makeBins (self, bin_width=100, count=0, max_size=0):
        """This function makes bins. If count is 0, then all bins are created
        up to max_size. If count is defined, then as many as the 'count' bins
        with the determined width will be created, and the last 'count+1'th bin
        will include the remaining.
        """
        if (max_size != 0):
            self.__max_size = max_size

        if (count==0):
            n = math.ceil (self.__max_size/self.__w)+1
            self.__bins = [i*self.__w for i in range (n)]
        else:
            n = count
            self.__bins = [i*self.__w for i in range (n)]
            self.__bins.append (self.__max_size)
        return

def get_ftbl_histogram (ftbl, feat='pkt_cnt'):
    """Returns numpy.histogram of a flow table.
    feat determines the feature to apply the histogram on.
    feat can be any of the following strings:
        pkt_cnt: histogram based on packet counts (default)
        pkt_len: histogram based on total packet length
        avg_len: histogram based on average packet length
    """
    data = []
    if (feat == 'pkt_cnt'):
        for f in ftbl:
            data.append (f.dif_cnt)
    elif (feat == 'pkt_cnt'):
        for f in ftbl:
            data.append (f.dif_len)
    elif (feat == 'avg_len'):
        for f in ftbl:
            data.append (f.dif_len/f.dif_cnt)

    if (len (data)==0):
        data.append (0)

    print ('length:', len(data))
    # print (data)
    hist = Histogram (max_size=65535)
    hist.makeBins (bin_width=100, count=20)
    hist.makeHistogram (data)
    t = np.sum (hist.hist)
    for h in hist.hist:
        s = '*'
        for _ in range (int (h/t*50)):
            s+='*'
        print ('{:5.2f}'.format(h/t), s)
    # exit()
    return hist



    

    

