class SimulationTime_meta(type):
    @classmethod
    def initialize (cls, basetime=0, simtime=0, timewin=5.0):
        cls.__basetime = basetime
        cls.__simtime = simtime
        cls.__timewin = timewin

    @property
    def simtime (cls):
        return cls.__simtime
    
    @property
    def basetime (cls):
        return cls.__basetime

    @property
    def timewin (cls):
        return cls.__timewin
    
    @property
    def nowtime (cls):
        return cls.__simtime + cls.__basetime    

    @classmethod
    def advance (cls, t=None):
        if (t != None):
            cls.__simtime += t
        else:
            cls.__simtime += cls.__timewin
        return cls.__simtime
    

    # @simtime.setter
    # def simtime (cls, t):
    #     cls.__simtime = t
    #     return

    # @basetime.setter
    # def basetime (cls, t):
    #     cls.__basetime = t
    #     return


class SimulationTime (metaclass=SimulationTime_meta):
    pass


if __name__ == "__main__":
    SimulationTime.initialize(basetime=517, simtime=5)
    print (SimulationTime.basetime, SimulationTime.simtime)
    SimulationTime.advance ()
    print (SimulationTime.basetime, SimulationTime.simtime)
    SimulationTime.advance (8)
    print (SimulationTime.basetime, SimulationTime.simtime)
    SimulationTime.simtime=51
    print (SimulationTime.basetime, SimulationTime.simtime)
    SimulationTime.basetime=5698
    print (SimulationTime.basetime, SimulationTime.simtime)
    print (SimulationTime.nowtime)

