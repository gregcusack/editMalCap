from statistics import stdev

# Flows contain a list of pkts sharing a mutual 5 tuple (proto, srcIP, srcPort, dstIP, dstPort)
class Flow:
    def __init__(self, flow_tuple):
        self.pkts = []
        self.flowStats = FlowStats()
        self.flowKey = flow_tuple

    def addPkt(self, pkt):
        self.pkts.append(pkt)

    def calcPktLenStats(self):
        self.flowStats.updateLenStats(self.pkts)

    def calcPktIAStats(self):
        self.flowStats.updateIAStats(self.pkts)

    def __repr__(self):
        return "<Flow: {}: #pkts: {}>".format(self.flowKey, self.flowStats.flowLen)


class FlowStats():
    def __init__(self):
        self.minLen = self.maxLen = self.avgLen = self.stdLen = 0
        self.minIA = self.maxIA = self.avgIA = self.stdIA = self.totalIA = 0
        self.flowLen = 0

    def __repr__(self):
        return "<LengthStats: min: {}, max: {}, avg: {}, std: {}, len: {}>\n<IAStats: min: {}, max: {}, avg: {}, std:{}>"\
            .format(self.minLen, self.maxLen, self.avgLen, self.stdLen, self.flowLen,
                    self.minIA, self.maxIA, self.avgIA, self.stdIA)

    def updateLenStats(self, pktList):
        self.flowLen = len(pktList)
        self.getMinMaxAvgLen(pktList)
        self.getStdLen(pktList)

    def updateIAStats(self, pktList):
        self.getMinMaxAvgIA(pktList)
        self.getStdIA(pktList)

    def getMinMaxAvgLen(self, pktList):
        total = 0
        self.minLen = self.maxLen = pktList[0].frame_len
        for pkt in pktList:
            if pkt.frame_len > self.maxLen:
                self.maxLen = pkt.frame_len
            elif pkt.frame_len < self.minLen:
                self.minLen = pkt.frame_len
            total += pkt.frame_len
        self.avgLen = total / self.flowLen

    def getStdLen(self, pktList):
        self.stdLen = stdev(pkt.frame_len for pkt in pktList)
        if self.stdLen < 0:
            print("ERROR: Std Dev. len < 0.  std val is: {}".format(self.stdLen))
            exit(-1)

    def getMinMaxAvgIA(self, pktList):
        total = 0
        iterable = iter(pktList)
        prev = next(iterable)
        self.minIA = prev.ts
        for pkt in iterable:
            diff = pkt.ts - prev.ts
            if diff > self.maxIA:
                self.maxIA = diff
            elif diff < self.minIA:
                self.minIA = diff
            total += diff
            prev = pkt
            # test
            if diff < 0:
                print("ERROR: Packets out of order! Diff < 0.  Diff={}".format(diff))
        self.avgIA = total / (self.flowLen - 1)

    def getStdIA(self, pktList):
        self.stdIA = stdev([j.ts - i.ts for i,j in zip(pktList[:-1], pktList[1:])])


class FlowTable:
    def __init__(self):               # list is our config list
        # have tables as all caps (and acronyms)
        self.FT = {}

    def procPkt(self, pkt):
        self.addFlow(pkt)

    def addFlow(self, pkt):
        if pkt.flow_tuple not in self.FT:
            self.FT[pkt.flow_tuple] = Flow(pkt.flow_tuple)
        self.FT[pkt.flow_tuple].addPkt(pkt)


class FlowFilter:
    def __init__(self, list): #TODO: this list needs to be the global config_file
        self.tuple_set = set(list) # convert dict of flows to set (aka left with just the dict keys)

    def needsTrans(self, pkt_5_tuple):
        #pkt needs to be a TransPkt type
        if pkt_5_tuple in self.tuple_set:
            return True
        return False