import numpy as np
import math

def entropy_old (tbl):
    """ Calculate entropy of each column of the given tbl.
    The tbl is a nxm numpy object.
    The function returns a m elements numpy array
    """
    if ((tbl < 0).any()):
        print ("ERR: The tbl has some negative entries. All entries must be positive.")
        return None

    # Each column must have at least one non-zero element.
    # If any column has all zero elements (sum is zero), then set all elements to 1 to get a
    # zero on the entropy of that column
    sums = tbl.sum (axis=0)
    for i in range(len(sums)):
        if sums[i]==0:
            tbl [:, i] = 1

    p = tbl/tbl.sum (axis=0) # Get probability of each cell
    if (len (p[p==0])>0): # NOT SURE IF THIS IS NECESSARY
        print ("ERROR WITH entropy()")
    
    # All values must fall between 0 and 1. Iny value is 0, then set it to 1 to get a zero
    # in the entropy (log(1) = 1)
    p[p==0] = 1

    # logp = np.where(p>0, np.log(p), 0) # consider 0 for entries of p that are not positive
    # t3 = time.time()
    logp = np.log(p)
    # t4 = time.time()
    plogp = -np.multiply (p, logp)
    # t5 = time.time()
    # print ('%.2f %.2f %.2f %.2f '%(t2-t1, t3-t2, t4-t3, t5-t4))
    return plogp.sum (axis=0) # sum over columns, and return a list of entries

def entropy (tbl):
    """ Calculate entropy of each column of the given tbl.
    The tbl is a nxm numpy object.
    The function returns a m elements numpy array
    """
    if ((tbl < 0).any()):
        print ("ERR: The tbl has some negative entries. All entries must be positive.")
        return None

    # Each column must have at least one non-zero element.
    # If any column has all zero elements (sum is zero), then set all elements to 1 to get a
    # zero on the entropy of that column
    sums = tbl.sum (axis=0)
    for i in range(len(sums)):
        if sums[i]==0:
            tbl [:, i] = 1

    N = tbl.sum (axis=0)
    n = tbl # Get probability of each cell
    if (len (n[n==0])>0): # NOT SURE IF THIS IS NECESSARY
        print ("ERROR WITH entropy()")
    
    # All values must fall between 0 and 1. Iny value is 0, then set it to 1 to get a zero
    # in the entropy (log(1) = 1)
    n[n==0] = 1

    # logp = np.where(p>0, np.log(p), 0) # consider 0 for entries of p that are not positive
    # t3 = time.time()
    logn = np.log(n)
    # t4 = time.time()
    nlogn = -np.multiply (n, logn)
    # t5 = time.time()
    # print ('%.2f %.2f %.2f %.2f '%(t2-t1, t3-t2, t4-t3, t5-t4))
    
    return nlogn.sum (axis=0)/N + np.log(N) # sum over columns, and return a list of entries
