# import structures
import sys
def eprint(*args, **kwargs):
    """This function will print the given arguments to STDERR
    """
    print(*args, file=sys.stderr, **kwargs)

def ipStr2Hex (ipStr):
    """Convert ip string from dot-separated decimal into a hexadecimal string."""
    a = ipStr.split('.')
    return '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, a))

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


