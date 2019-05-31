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


class HashCollection:
    """This class is made only to keep track of the flows in various modules"""
    fl  = dict()  # flows
    sip = dict()  # source IP
    dip = dict()  # destination IP
    sp  = dict()  # source port
    dp  = dict()  # destination port


