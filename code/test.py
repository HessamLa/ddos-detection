#!/usr/bin/env py3

import time
import random
import numpy as np
from structures import *
import copy

from multiprocessing import Process
from multiprocessing import Pool
import os


def process_info(title):
    print ('Process title:', title)
    print ('module name:', __name__)
    if hasattr(os, 'getppid'):  # only available on Unix
        print ('parent process:', os.getppid())
    print ('process id:', os.getpid())

def f(args):
    ID = 0
    print (args)
    name, ID = args

    print ('')
    process_info ('function f')
    print ('hello', name, ID, '.')


class dictest():
    def __init__ (self, N):
        self.N = N
        self.__tbls = [BaseTable() for i in range (self.N)]

        import concurrent.futures
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=N)
        return

    def setitem (self, key, value):
        tblid=key & (self.N-1)
        # self.__tbl [key] = value
        self.executor.submit (self.__tbls[tblid].setitem, key, value)
        return

    def getitem (self, key):
        tblid=key & (self.N-1)
        try:
            value = self.executor.submit (self.__tbls[tblid].getitem, key).result()
        except:
            return None
        return value





class base1:
    def __init__ (self, n):
        if  (n != None):
            self.n = n

class ctest (base1):
    count = 0
    def __init__ (self, n=None):
        base1.__init__ (self, n=n)
        ctest.value = 3
        self.iobj = "X"
        return

    def copy (self):
        return copy.copy (self)

    def printn (self):
        print (self.n)

def test(*a, **b):
    for v in a:
        print (v)

    for k,v in b.items():
        print (k, v)


class Obj ():
    def __init__ (self, a, b, c, *args):
        self.a = a
        self.b = b
        self.c = c
        self.lst = []
        for a in args:
            self.lst.append (a)

    def __repr__ (self):

        # print ("a, b, c:", self.a, self.b, self.c)
        s="a, b, c: "+str(self.a) +' '+ str(self.b) +' ' + str (self.c)
        s += '\n'
        for a in self.lst:
            s+= str(a)+'-'
        return s

if __name__ == "__main__":
    test (1,'hg', a=1, jam=8.2)

    import numpy as np
    from math import ceil
    import random
    import time
    
    
    def do_obj (obj):
        obj.x = obj.a+obj.b

    obj =[]
    w = 1000000
    for i in range (w):
        obj.append (Obj (i,i*10,i*100+10, i,i,i))
    print (obj[11])
    for o in obj:
        do_obj (o)
    
    exit ()

    
    w = 1000
    bins = [i*w for i in range (ceil (65535/w)+1)]
    print (bins)

    def do_log2 (arr):
        t0 = time.time()
        for i in range (len (arr)):
            try:
                a = np.log2 (arr[i])
            except:
                print (arr[i])
                
        print ("time log2:", time.time() - t0)

    def do_log10 (arr):
        t0 = time.time()
        for i in range (len (arr)):
            try:
                a = np.log10 (arr[i])
            except:
                print (arr[i])
                
        print ("time log10:", time.time() - t0)

    def do_log (arr):
        t0 = time.time()
        for i in range (len (arr)):
            try:
                a = np.log (arr[i])
            except:
                print (arr[i])
                
        print ("time log_e:", time.time() - t0)

    maxx = 100000
    arr = np.arange(1, 1001, 100/maxx)
    random.shuffle (arr)
    print ("made the thing")


    do_log (arr)
    do_log2 (arr)
    do_log10 (arr)
    do_log (arr)
    do_log2 (arr)
    do_log10 (arr)
    do_log (arr)
    do_log2 (arr)
    do_log10 (arr)
    exit ()
    
    maxx = 10000000
    d = dict()
    print ("filling up the table")
    for i in range (maxx):
        if (i%100000==0):
            print (i)
        r = random.random ()
        # index = int (maxx*r)
        index = hash (r)
        d [index] = r

    max_iter = 10
    
    t_total = 0
    for i in range (max_iter):
        t0 = time.time ()
        a=0
        for v in d.values():
            if (v < 0.001):
                a+=1
        t1 = time.time ()
        t_total += t1-t0
    print ("Third experiment 'for v in d.values():'\n time avg:", t_total/max_iter, "a=", a)

    t_total = 0
    for i in range (max_iter):
        t0 = time.time ()
        a=0
        for index in d:
            if (d[index] < 0.001):
                a+=1
        t1 = time.time ()
        t_total += t1-t0
    print ("First experiment 'for index in d:'\n time avg:", t_total/max_iter, "a=", a)
    
    t_total = 0
    for i in range (max_iter):
        t0 = time.time ()
        a=0
        for index, v in d.items():
            if (v < 0.001):
                a+=1
        t1 = time.time ()
        t_total += t1-t0
    print ("Second experiment 'for index, v in d.items():'\n time avg:", t_total/max_iter, "a=", a)




    
    # print (bins)
