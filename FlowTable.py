from TransPkt import TransPkt

class FlowTable:
    def __init__(self):               # list is our config list
        # has tables as all caps (and acronyms)
        self.FT = {}
        self.L_TS = {}               # dict to maintain ts of last seen pkt of flow (last_timestamp)

    def addFlow(self, pkt):
        if pkt.flow_tuple not in self.FT:
            self.FT[pkt.flow_tuple] = []

        self.FT[pkt.flow_tuple].append(pkt)
        self.updateLastTs(pkt)

    def delFlow(self, pkt_5_tuple):
        try:
            del self.FT[pkt_5_tuple]
        except KeyError:
            print("Flow 5 Tuple does not exist in Flow Table")
            exit(0)

    def updateLastTs(self, pkt):
        self.L_TS[pkt.flow_tuple] = pkt.ts


class FlowFilter:
    def __init__(self, list): #TODO: this list needs to be the global config_file
        self.tuple_set = set(list)

    def needsTrans(self, pkt):
        #pkt needs to be a TransPkt type
        if pkt.flow_tuple in self.tuple_set:
            return True
        return False