import structures
import sys
"""
This function will print the given arguments to STDERR
"""
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def ipStr2Hex (ipStr):
    a = ipStr.split('.')
    return '{:02X}{:02X}{:02X}{:02X}'.format(*map(int, a))