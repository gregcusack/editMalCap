from statistics import stdev

# Flows contain a list of pkts sharing a mutual 5 tuple (proto, srcIP, srcPort, dstIP, dstPort)
class Flow:
    def __init__(self, flow_tuple):
        self.pkts = []
        self.flowStats = FlowStats()
        self.flowKey = flow_tuple
        self.biFlowKey = (flow_tuple[0], flow_tuple[3], flow_tuple[4], flow_tuple[1], flow_tuple[2])
        self.biPkts = None
        self.procFlag = None
        self.diffs = []
        #print(self.flowKey)
        #print(self.biFlowKey)

    def addPkt(self, pkt):
        self.pkts.append(pkt)

    def calcPktLenStats(self):
        self.flowStats.updateLenStats(self.pkts)

    # def incLenStats(self, pktLen):
    #     self.flowStats.getIncLenStats(pktLen)
    #
    # def incSplitLenStats(self, oPktLen, nPkt1Len, nPkt2Len):      # lenPktPreSplit, newPktLen1, newPktLen2
    #     self.flowStats.updateSplitIncLenStats(oPktLen, nPkt1Len, nPkt2Len, self.pkts)

    def calcPktIAStats(self):
        self.flowStats.updateIAStats(self.pkts)

    def getDiffs(self):
        print("getting DIFFS!")
        i = j = k = 0
        if self.pkts[0] < self.biPkts[0]:
            prev_ts = self.pkts[0].ts
            self.diffs.append(('F', 0))
            i += 1
        elif self.pkts[0] > self.biPkts[0]:
            prev_ts = self.biPkts[0].ts
            self.diffs.append(('B', 0))
            j += 1
        else:
            prev_ts = self.biPkts[0].ts
            self.diffs.append(('S', 0))
            i += 1
            j += 1
        print(i, j, prev_ts)

        if self.flowStats.flowLen > len(self.biPkts):
            length = self.flowStats.flowLen
        else:
            length = len(self.biPkts)
        print(length)

        for n in range(length):
            if self.pkts[i] < self.biPkts[j]:
                self.diffs.append(("F", self.pkts[i].ts - prev_ts))
                prev_ts = self.pkts[i].ts
                i += 1
            elif self.pkts[i] > self.biPkts[j]:
                self.diffs.append(("B", self.biPkts[j].ts - prev_ts))
                prev_ts = self.biPkts[j].ts
                j += 1
            else:
                self.diffs.append(("S", self.biPkts[j].ts - prev_ts))
                prev_ts = self.biPkts[j].ts
                i += 1
                j += 1
            k += 1
        print(self.diffs)

    def __repr__(self):
        return "<Flow: {}: #pkts: {}>".format(self.flowKey, self.flowStats.flowLen)


class FlowStats():
    def __init__(self):
        self.minLen = self.maxLen = self.avgLen = self.stdLen = 0
        self.minIA = self.maxIA = self.avgIA = self.stdIA = self.totalIA = 0
        self.flowLen = 0
        self.flowLenBytes = 0

    def __repr__(self):
        return "<LengthStats: min: {}, max: {}, avg: {}, std: {}, len: {}, lenBytes: {}>\n<IAStats: min: {}, max: {}, avg: {}, std:{}>"\
            .format(self.minLen, self.maxLen, self.avgLen, self.stdLen, self.flowLen, self.flowLenBytes,
                    self.minIA, self.maxIA, self.avgIA, self.stdIA)

    def updateLenStats(self, pktList):
        self.resetLenStats()
        self.flowLen = len(pktList)
        self.getMinMaxAvgLen(pktList)
        self.getStdLen(pktList)

    def updateIAStats(self, pktList):
        self.resetIAStats()
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
        self.flowLenBytes = total

    def getStdLen(self, pktList):
        self.stdLen = stdev(pkt.frame_len for pkt in pktList)
        if self.stdLen < 0:
            print("ERROR: Std Dev. len < 0.  std val is: {}".format(self.stdLen))
            exit(-1)

    def resetIAStats(self):
        self.minIA = self.maxIA = self.avgIA = self.stdIA = self.totalIA = 0

    def resetLenStats(self):
        self.minLen = self.maxLen = self.avgLen = self.stdLen = 0
        self.flowLen = 0
        self.flowLenBytes = 0

    def getMinMaxAvgIA(self, pktList):
        total = 0
        iterable = iter(pktList)
        prev = next(iterable)
        self.minIA = prev.ts
        for pkt in iterable:
            diff = pkt.ts - prev.ts
            if diff > self.maxIA:
                self.maxIA = diff
                # print("maxIA: {}".format(self.maxIA))
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
        self.filter = filter

    def procPkt(self, pkt, transFlow):
        self.addFlow(pkt, transFlow)

    def addFlow(self, pkt, transFlow):
        if pkt.flow_tuple not in self.FT:
            self.FT[pkt.flow_tuple] = Flow(pkt.flow_tuple)
            if transFlow == "Trans":
                self.FT[pkt.flow_tuple].procFlag = True
            elif transFlow == "NoTrans":
                self.FT[pkt.flow_tuple].procFlag = False
            else:
                print("ERROR: Invalid string")
                exit(-1)
        self.FT[pkt.flow_tuple].addPkt(pkt)

class FlowFilter:
    def __init__(self, list): #TODO: this list needs to be the global config_file
        self.tuple_set = set(list) # convert dict of flows to set (aka left with just the dict keys)

    def needsTrans(self, pkt_5_tuple):
        biTuple = (pkt_5_tuple[0], pkt_5_tuple[3], pkt_5_tuple[4], pkt_5_tuple[1], pkt_5_tuple[2])
        #pkt needs to be a TransPkt type
        if pkt_5_tuple in self.tuple_set:
            return "Trans"
            # add and transform flag = true
        elif biTuple in self.tuple_set:
            return "NoTrans"
        else:
            return False
            # don't add
        #     return True
        # return False