# import structures
import sys
import math

def eprint(*args, **kwargs):
    """This function will print the given arguments to STDERR
    """
    print(*args, file=sys.stderr, **kwargs)

def ipStr2Hex (ipStr):
    """Convert ip string from dot-separated decimal into a hexadecimal string."""
    a = ipStr.split('.')
    return '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, a))

def log2cat (v, max_cat):
  """
  Categories are as follows:
  cat |  v
   0  |  0
   1  |  1
   2  |  2-3
   3  |  4-7
   4  |  8-15  
  """
  try:
    cat  = int (math.ceil (math.log2 (v+1)))
  except:
    print ("Exception raised\n log2 method, Cnt:",v+1)
  return min (cat, max_cat)

def log10cat_1_off (v, max_cat):
  """
  Categories are as follows:
  cat |  v
   0  |  0
   1  |  1
   2  |  2-10
   3  | 11-100
   4  |101-1000
   ...
  """
  try:
    cat = 1+int (math.ceil (math.log10 (v)))
  except ValueError:
    if (v == 0): return 0
  except:
    print ("Exception raised\n log10 method, Cnt:",v)
  return min (cat, max_cat)

def getflowcat (f, cat_method, custom_cats=None, max_cat=999999):
  """ Gets flow category. This catgory can be used as an index for other applications
    f: a FlowEntry
    cat_method: an integer representing the required category. It can be one of the following.
        0:  log2-based packet count
        1: log10-based packet count 
        2:  log2-based packet size
        3: log10-based packet size
        4: customized category. This requires 'custom_cats' to be defined
  """
  methods = [
    lambda f, max_cat: log2cat(f.dif_cnt, max_cat),
    lambda f, max_cat: log10cat_1_off(f.dif_cnt, max_cat),
    lambda f, max_cat: log2cat(f.dif_len, max_cat),
    lambda f, max_cat: log10cat_1_off(f.dif_len, max_cat)
  ]
  try:
    ret = methods [cat_method](f, max_cat)
  except:
    print ("getflowcat(), cat_method:", cat_method)
  return ret


def getflowcat_old (f, cat_method, categories=None, max_cat=999999):
    """ Gets flow category. This catgory can be used as an index for other applications
    f: a FlowEntry
    cat: a string representing the required category
    """
    if (cat_method == "log2pktcnt"):
      try:
        cat  = int (math.ceil (math.log2 (f.dif_cnt+1)))
      except:
        print ("Exception raised\n", cat_method, ", Cnt:",f.dif_cnt)
      return min (cat, max_cat)

    elif (cat_method == "log10pktcnt"):
      try:
        cat  = 1+int (math.ceil (math.log10 (f.dif_cnt)))
      except ValueError:
        if (f.dif_cnt == 0): return 0
      return min (cat, max_cat)
    
    elif (cat_method == "log2pktlen"):
      try:
        cat = int (math.ceil (math.log2 (f.dif_len+1)))
      except:
        print ("Exception raised\n", cat_method, ", Cnt:",f.dif_len)
      return min (cat, max_cat)

    elif (cat_method == "log10pktlen"):
      try:
        cat = 1+int (math.ceil (math.log10 (f.dif_len)))
      except:
        print ("Exception raised\n", cat_method, ", Cnt:",f.dif_len)
      return min (cat, max_cat)
      
    else:
      print ("ERR: category unknown:", cat, "max:", max_cat)
      exit ()
    return None

def first_elements (obj, n):
  i = 0
  for v in obj:
    if i < n:
      yield v
    else:
      return
    i+=1
  return

class COLOR_CODE:
    """
    NC = '\033[m' # no-color
    bold = '\033[1m' # bold
    ulin = '\033[4m' # underline
    invt = '\033[7m' # inverted
    rset = '\033[0m' # reset all attributes
    BLK  = '\033[30m' # black
    RED  = '\033[31m' # red
    GRN  = '\033[32m' # green
    YLW  = '\033[33m' # yellow
    MGT  = '\033[35m' # magenta
    CYN  = '\033[36m' # cyan
    """
    NC = '\033[m' # no-color
    bold = '\033[1m' # bold
    ulin = '\033[4m' # underline
    invt = '\033[7m' # inverted
    rset = '\033[0m' # reset all attributes
    BLK  = '\033[30m' # black
    RED  = '\033[31m' # red
    GRN  = '\033[32m' # green
    YLW  = '\033[33m' # yellow
    MGT  = '\033[35m' # magenta
    CYN  = '\033[36m' # cyan

class HashCollection:
    """This class is made only to keep track of the flows in various modules"""
    fl  = dict()  # flows
    sip = dict()  # source IP
    dip = dict()  # destination IP
    sp  = dict()  # source port
    dp  = dict()  # destination port


import time
class tlog():
  tstart=0
  tend=0
  def __init__(self):
    return
  @classmethod
  def start(cls):
    cls.tstart = time.time()
    return cls.tstart
  @classmethod
  def diff(cls):
    return time.time()-cls.tstart
  @classmethod
  def end(cls):
    cls.tend = time.time()
    return cls.tend



