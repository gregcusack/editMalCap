from TransPkt import TransPkt

class FlowTable:
    def __init__(self):               # list is our config list
        # have tables as all caps (and acronyms)
        self.FT = {}
        self.L_TS = {}               # dict to maintain ts of last seen pkt of flow (last_timestamp)

    def procPkt(self, pkt):
        self.addFlow(pkt)
        self.updateLastTs(pkt)

    def addFlow(self, pkt):
        if pkt.flow_tuple not in self.FT:
            self.FT[pkt.flow_tuple] = []

        self.FT[pkt.flow_tuple].append(pkt)

    def delFlow(self, pkt_5_tuple):
        try:
            del self.FT[pkt_5_tuple]
        except KeyError:
            print("ERROR: Flow 5 Tuple does not exist in Flow Table. Offending key: {}".format(pkt_5_tuple))
            exit(-1)
        try:
            del self.L_TS[pkt_5_tuple]
        except KeyError:
            print("ERROR: Flow 5 Tuple does not exist in L_TS. Offending key: {}".format(pkt_5_tuple))
            exit(-1)

    def updateLastTs(self, pkt):                # using PCAPs, store pkt time, compare each incoming pkt across all pkts
        self.L_TS[pkt.flow_tuple] = pkt.ts*1000 #time.time() * 1000 #store current time in ms


class FlowFilter:
    def __init__(self, list): #TODO: this list needs to be the global config_file
        self.tuple_set = set(list) # convert dict of flows to set (aka left with just the dict keys)

    def needsTrans(self, pkt_5_tuple):
        #pkt needs to be a TransPkt type
        if pkt_5_tuple in self.tuple_set:
            return True
        return False