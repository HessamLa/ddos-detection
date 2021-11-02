import sys
from pathlib import Path
import pickle
from typing import Pattern

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
    
    def close (self):
        if (self.f):
            self.f.close()
        return

class pickle_write:
    def __init__ (self, filepath, mode='wb', partition_size=None):
        """partition size is given in bytes"""
        self.name = filepath
        self.partition_size = partition_size
        self.file_id = 0
        self.filepath_base = filepath
        if(partition_size==None):
            self.filepath = self.filepath_base
        else:
            self.filepath = f"{self.filepath_base}-{self.file_id:04d}"
        self._open(mode)
        
    def _open(self, mode="wb"):
        try:
            self._f = open(self.filepath, mode)
        except:
            eprint ("ERR: Failed to open/create the file", self.filepath)
            eprint ("pickle_write.__init__()")
            raise

    def partition_if_required(self):
        """This method will check if the destination file size. If the file quota is passed, it will close the current
        file and open another file. It will increment the filename number by one."""
        if(self.partition_size == None):
            return
        if (Path(self.filepath).stat().st_size < self.partition_size):
            return
        self.close_file()
        self.file_id += 1
        self.filepath = f"{self.filepath_base}-{self.file_id:04d}"
        print("NEW PARTITION", self.filepath)
        self._open()

    def dump (self, obj):
        self.partition_if_required()
        try:
            pickle.dump (obj, self._f)
        except:
            eprint ("ERR: Problem dumping the pickle to", self.filepath)
            eprint ("pickle_write.dump()")
            raise
        return
    
    def close (self):
        if (self._f):
            self._f.close()
        return

if __name__ == "__main__":
    path="/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-any-k0.ent"
    reader = pickle_read(path)
    obj = reader.load()
    print (obj)