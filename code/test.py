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
    def __init__ (self):
        return

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

if __name__ == "__main__":
    c1  = ctest()
    c2 = ctest()
    c3 = c2.copy ()
    c2.iobj = "OOO"
    print (c1.count, c1.value, c1.iobj)
    print (c2.count, c2.value, c2.iobj)
    print (c3.count, c3.value, c3.iobj)

    c4  = ctest(n=6)
    # print (c4.n)
    c4.printn ()

    MAX = 10000
    a = [random.random() for i in range (MAX)]
    loga = np.log(a)
    print (loga)

    p = Pool(2)
    p.map(f, [('bob', 5),('jack',111)])
    # p = Process(target=f, args=('bob', 5,))
    # p.start()
    # p.join()

    import numpy as np
    import matplotlib.pyplot as plt
    from matplotlib.widgets import Slider, Button, RadioButtons

    fig, ax = plt.subplots()
    plt.subplots_adjust(left=0.25, bottom=0.25)
    t = np.arange(0.0, 1.0, 0.001)
    a0 = 5
    f0 = 3
    s = a0*np.sin(2*np.pi*f0*t)
    l, = plt.plot(t, s, lw=2, color='red')
    plt.axis([0, 1, -10, 10])

    axcolor = 'lightgoldenrodyellow'
    axfreq = plt.axes([0.25, 0.1, 0.65, 0.03], facecolor=axcolor)
    axamp = plt.axes([0.25, 0.15, 0.65, 0.03], facecolor=axcolor)

    sfreq = Slider(axfreq, 'Freq', 0.1, 30.0, valinit=f0)
    samp = Slider(axamp, 'Amp', 0.1, 10.0, valinit=a0)


    def update(val):
        amp = samp.val
        freq = sfreq.val
        l.set_ydata(amp*np.sin(2*np.pi*freq*t))
        fig.canvas.draw_idle()
    sfreq.on_changed(update)
    samp.on_changed(update)

    resetax = plt.axes([0.8, 0.025, 0.1, 0.04])
    button = Button(resetax, 'Reset', color=axcolor, hovercolor='0.975')


    def reset(event):
        sfreq.reset()
        samp.reset()
    button.on_clicked(reset)

    rax = plt.axes([0.025, 0.5, 0.15, 0.15], facecolor=axcolor)
    radio = RadioButtons(rax, ('red', 'blue', 'green'), active=0)


    def colorfunc(label):
        l.set_color(label)
        fig.canvas.draw_idle()
    radio.on_clicked(colorfunc)

    plt.show()


