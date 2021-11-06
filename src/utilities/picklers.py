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
        try:
            obj = pickle.load (self.f)
        except:
            eprint ("ERR: Failed to open/read the file". self.filepath)
            eprint ("pickle_read.load()")
            exit()
        return obj

    def get_next (self):
        try:
            obj = pickle.load(self.f)
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
    def __init__ (self, filepath, mode='wb', filepath_ext="", partition_size=None):
        """partition size is given in bytes. The destination file will be opened after the first call to dump()"""
        self.name = filepath
        self.mode = mode
        self.partition_size = partition_size
        
        # set filepath
        self._f = None # the file handler will be initialized after the first call to dump()
        self.file_id = 0
        self.filepath_ext = filepath_ext
        self.filepath_base = filepath
        if(partition_size==None):
            self.filepath = f"{self.filepath_base}{self.filepath_ext}"
        else:
            self.filepath = f"{self.filepath_base}-{self.file_id:04d}{self.filepath_ext}"

        
    def _open(self):
        try:
            self._f = open(self.filepath, self.mode)
        except:
            eprint ("ERR: Failed to open/create the file", self.filepath)
            eprint ("pickle_write.__init__()")
            raise

    def partition_if_required(self):
        """This method will check if the destination file size. If the file quota is passed, it will close the current
        file and open another file. It will increment the filename number by one."""
        if(self._f == None):
            self._open()
        if(self.partition_size == None):
            return
        if (Path(self.filepath).stat().st_size < self.partition_size):
            return
        self.close()
        self.file_id += 1
        self.filepath = f"{self.filepath_base}-{self.file_id:04d}{self.filepath_ext}"
        self._open()
        print("NEW PARTITION", self.filepath)

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

def pickle_dump(filepath, obj, mode="wb"):
    file = open(filepath, mode=mode)
    pickle.dump(obj, file)
    file.close()

if __name__ == "__main__":
    path="/N/slate/hessamla/ddos-datasets/caida/output-t10/caida-t10-cftbl-any-k0.ent"
    reader = pickle_read(path)
    obj = reader.load()
    print (obj)