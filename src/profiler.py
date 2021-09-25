class Profiler_meta(type):
    @classmethod
    def initialize (cls, info='', datasetname='', datasetdir='', datsettype='',
                    nshotsdir='', switchname='', timewin='', basedir='', outdir='',
                    entropypath='', statspath='', catmethod=''):
        cls.__info      = info
        cls.__dsname    = datasetname
        cls.__dsdir     = datasetdir
        cls.__nshotsdir = nshotsdir
        cls.__swname    = switchname
        cls.__timwin    = timewin
        cls.__basedir   = basedir
        cls.__outdir    = outdir
        cls.__entpath   = entropypath
        cls.__statspath = statspath
        cls.__catmethod = catmethod
        return

    def __get_info (cls):
        return cls.__info   
    def __set_info (cls, v):
        cls.__info   = v
    info = property (__get_info, __set_info)

    def __get_datasetname (cls):
        return cls.__dsname   
    def __set_datasetname (cls, v):
        cls.__dsname   = v
    datasetname = property (__get_datasetname, __set_datasetname)
    
    def __get_datasetdir (cls):
        return cls.__dsdir    
    def __set_datasetdir (cls, v):
        cls.__dsdir    = v
    datasetdir = property (__get_datasetdir, __set_datasetdir)
    
    def __get_nshotsdir (cls):
        return cls.__nshotsdir
    def __set_nshotsdir (cls, v):
        cls.__nshotsdir= v
    nshotsdir = property (__get_nshotsdir, __set_nshotsdir)
    
    def __get_switchname (cls):
        return cls.__swname   
    def __set_switchname (cls, v):
        cls.__swname   = v
    switchname = property (__get_switchname, __set_switchname)
    
    def __get_timewin (cls):
        return cls.__timwin   
    def __set_timewin (cls, v):
        cls.__timwin   = float(v)
    timewin = property (__get_timewin, __set_timewin)
    
    def __get_basedir (cls):
        return cls.__basedir  
    def __set_basedir (cls, v):
        cls.__basedir  = v
    basedir = property (__get_basedir, __set_basedir)
    
    def __get_outdir (cls):
        return cls.__outdir  
    def __set_outdir (cls, v):
        cls.__outdir  = v
    outdir = property (__get_outdir, __set_outdir)

    def __get_entpath (cls):
        return cls.__entpath  
    def __set_entpath (cls, v):
        cls.__entpath  = v
    entropypath = property (__get_entpath, __set_entpath)

    def __get_statspath (cls):
        return cls.__statspath
    def __set_statspath (cls, v):
        cls.__statspath  = v
    statspath = property (__get_statspath, __set_statspath)
    
    def __get_catmethod (cls):
        return cls.__catmethod
    def __set_catmethod (cls, v):
        method_ids = {"log2pktcnt"   :0,
                      "log10pktcnt"  :1,
                      "log2pktlen"   :2,
                      "log10pktlen"  :3,
                      "custom_pktcnt":4,
                      "custom_pktlen":5}
        cls.__catmethod = method_ids [v] # convert from string to corresponding integer
    catmethod = property (__get_catmethod, __set_catmethod)


class Profiler (metaclass=Profiler_meta):
    pass


if __name__ == "__main__":
    Profiler.initialize ()
    print (Profiler.basedir)
    Profiler.timewin = 8
    print (Profiler.timewin)
    Profiler.initialize (switchname='Jack', outdir='./dmps')
    print (Profiler.outdir)
    pass
