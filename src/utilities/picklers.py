import sys
import pickle

from .helpers import eprint
# from datastructures import structures
# from datastructures.structures import FTDObj

class pickle_read:
    def __init__ (self, filepath: str):
        # from datastructures import structures
        self.filepath = filepath
        mode='rb'
        self.f = open(filepath, mode)
        if (self.f is None):
            eprint ("ERR: Openning FTD file", filepath)
            eprint ("pickle_read.__init__()")
            exit()
        return

    def load (self):
        # print("inside pickle_read.load()")
        try:
            # print("inside pickle_read.load() try")
            obj = pickle.load (self.f)
        except:
            eprint ("ERR: Failed to open/read the file". self.filepath)
            eprint ("pickle_read.load()")
            exit()
        return obj

    def get_next (self):
        # from datastructures import structures
        # print("pickle_read.get_next()")
        # obj = pickle.load(self.f)
        # print("pickle_read.get_next()", type(obj))
        try:
            # print("inside pickle_read.get_next()")
            obj = pickle.load(self.f)
            # print("pickle_read.get_next() 2", type(obj))
        except EOFError:
            return None
        except:
            eprint("pickle_read.get_next() Unknown exception")
            raise
        return obj
    
    def objects (self):
        while (True):
            try:
                obj = pickle.load(self.f)
                yield obj
            except EOFError:
                return
            except:
                eprint("pickle_read.objects() Unknown exception")
                raise
    
    def close_file (self):
        if (self.f != None):
            self.f.close()
        return

class pickle_write:
    def __init__ (self, filepath, mode='wb'):
        self.name = filepath
        self.filepath = filepath
        try:
            self.f = open(self.filepath, mode)
        except:
            eprint ("ERR: Failed to open/create the file", self.filepath)
            eprint ("pickle_write.__init__()")
            exit ()
        return
    
    def dump (self, obj):
        try:
            pickle.dump (obj, self.f)
        except:
            eprint ("ERR: Problem dumping the pickle to", self.filepath)
            eprint ("pickle_write.dump()")
            exit ()
        return
    
    def close_file (self):
        if (self.f != None):
            self.f.close()
        return

if __name__ == "__main__":
    path="/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-any-k0.ent"
    reader = pickle_read(path)
    obj = reader.load()
    print (obj)