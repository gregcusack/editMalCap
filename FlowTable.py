from statistics import stdev

FLOWTIMEOUT = 120 # 120 seconds

# Flows contain a list of pkts sharing a mutual 5 tuple (proto, srcIP, srcPort, dstIP, dstPort)
class Flow:
    def __init__(self, flow_tuple, _flow_start_time, timeout):
        self.pkts = []
        self.flowStats = FlowStats()
        self.flowKey = flow_tuple
        self.flow_timeout = timeout
        self.biFlowKey = None
        self.flowStartTime = _flow_start_time
        self.flowEndTime = 0
        if flow_tuple[0] == 6:
            self.biFlowKey = (flow_tuple[0], flow_tuple[3], flow_tuple[4], flow_tuple[1], flow_tuple[2])
        elif flow_tuple[0] == 17:
            self.biFlowKey = (flow_tuple[0], flow_tuple[3], flow_tuple[4], flow_tuple[1], flow_tuple[2]) # biflow: no dstPort being set as srcPort!
        else:
            print("Bad flow protocol...exiting")
            exit(-1)
        self.end_fin = False
        self.biPkts = None
        self.procFlag = None
        self.diffs = []
        self.oldFlowDuration = 0
        self.adj_flow_dir = 0 # this is set when fwd_iat_max > flow_duration...this becomes new adv_flow
        self.amount_flow_extended = 0

        #print(self.flowKey)
        #print(self.biFlowKey)

    def addPkt(self, pkt):
        self.pkts.append(pkt)

    def calcPktLenStats(self):
        self.flowStats.updateLenStats(self.pkts, self.biPkts)

    # def incLenStats(self, pktLen):
    #     self.flowStats.getIncLenStats(pktLen)
    #
    # def incSplitLenStats(self, oPktLen, nPkt1Len, nPkt2Len):      # lenPktPreSplit, newPktLen1, newPktLen2
    #     self.flowStats.updateSplitIncLenStats(oPktLen, nPkt1Len, nPkt2Len, self.pkts)

    def calcPktIAStats(self):
        self.flowStats.updateIAStats(self.pkts, self.biPkts)

    def get_1D_diffs(self):
        self.diffs = []
        self.diffs.append(("F", 0))
        prev_ts = self.pkts[0].ts
        for i in range(1, len(self.pkts)):
            diff = self.pkts[i].ts - prev_ts
            self.diffs.append(("F", diff))
            prev_ts = self.pkts[i].ts


    def getDiffs(self):
        # print("getting DIFFS!")
        self.diffs = []
        i = j = k = 0
        if self.pkts[0] < self.biPkts[0]:
            prev_ts = self.pkts[0].ts
            self.diffs.append(('F', 0))
            # print("F", self.pkts[i].ts)
            i += 1
        elif self.pkts[0] > self.biPkts[0]:
            prev_ts = self.biPkts[0].ts
            self.diffs.append(('B', 0))
            # print("B", self.biPkts[j].ts)
            j += 1
        else:
            prev_ts = self.biPkts[0].ts
            self.diffs.append(('S', 0))
            # print("S", self.pkts[i].ts, self.biPkts[j].ts)
            i += 1
            j += 1
        #print(i, j, prev_ts)

        length = self.getLongerFlow()
        f_len, b_len, total_bi_len = self.getLenFlowStats()
        #print(length)
        counter = 0
        # print("f_len: {}, b_len: {}, total_bi_len: {}".format(f_len, b_len, total_bi_len))
        # print(self.diffs[0][0], end=' ')
        for n in range(1, total_bi_len):
            if i != f_len and j != b_len:
                if self.pkts[i] < self.biPkts[j]:
                    prev_ts = self.updateDiffs(self.diffs, "F", self.pkts, i, prev_ts)
                    # print("F",self.pkts[i].ts)
                    i += 1
                elif self.pkts[i] > self.biPkts[j]:
                    prev_ts = self.updateDiffs(self.diffs, "B", self.biPkts, j, prev_ts)
                    # print("B", self.biPkts[j].ts)
                    j += 1
                else:
                    prev_ts = self.updateDiffs(self.diffs, "S", self.biPkts, j, prev_ts)
                    # print("S", self.pkts[i].ts, self.biPkts[j].ts)
                    i += 1
                    j += 1
                k += 1
            elif i == f_len and j != b_len:
                prev_ts = self.updateDiffs(self.diffs, "B", self.biPkts, j, prev_ts)
                # print("B", self.biPkts[j].ts)
                j += 1
            elif i != f_len and j == b_len:
                prev_ts = self.updateDiffs(self.diffs, "F", self.pkts, i, prev_ts)
                # print("F", self.pkts[i].ts)
                i += 1

            # print(self.diffs[-1][0], end=" ")
        # print("")
        #print(self.diffs)

    def updateDiffs(self, aList: list, dir: str, dList: list, index: int, prev_ts):
        #aList.append(DirTuple(dir, dList[index].ts - prev_ts))
        aList.append((dir, dList[index].ts - prev_ts))
        return dList[index].ts

    def getLenFlowStats(self):
        f_len = len(self.pkts)
        b_len = len(self.biPkts)
        total_bi_len = f_len + b_len
        return f_len, b_len, total_bi_len

    def getLongerFlow(self):
        return len(self.pkts) if len(self.pkts) > len(self.biPkts) else len(self.biPkts)

    def get_old_flow_duration(self):
        self.oldFlowDuration = self.flowStats.getFlowDuration(self.pkts, self.biPkts)

    def __repr__(self):
        return "<Flow: {}: #pkts: {}>".format(self.flowKey, self.flowStats.flowLen)


class FlowStats():
    def __init__(self):
        self.minLen = self.maxLen = self.avgLen = self.stdLen = 0
        self.minIA = self.maxIA = self.avgIA = self.stdIA = self.totalIA = 0
        self.flowLen = 0
        self.flowLenBytes = 0
        self.flowDuration = 0
        self.maxLenIndex = self.minLenIndex = 0
        self.urgFlags = self.finFlags = self.synFlags = self.rstFlags = 0
        self.pshFlags = self.ackFlags = self.eceFlags = self.cweFlags = 0

    def __repr__(self):
        return "<LengthStats: min: {}, max: {}, avg: {}, std: {}, len: {}, lenBytes: {}>\n<IAStats: min: {}, max: {}, avg: {}, std:{}, flowDur: {}>"\
            .format(self.minLen, self.maxLen, self.avgLen, self.stdLen, self.flowLen, self.flowLenBytes,
                    self.minIA, self.maxIA, self.avgIA, self.stdIA, self.flowDuration)

    def updateLenStats(self, pktList, biPktList):
        self.resetLenStats()
        self.flowLen = len(pktList)
        self.getMinMaxAvgLen(pktList)
        self.getStdLen(pktList)
        self.getFlowDuration(pktList, biPktList)

    def updateIAStats(self, pktList, biPktList):
        self.resetIAStats()
        self.getMinMaxAvgIA(pktList)
        self.getStdIA(pktList)
        self.getFlowDuration(pktList, biPktList)

    def getMinMaxAvgLen(self, pktList):
        total = 0
        i = 0
        self.minLen = self.maxLen = pktList[0].pload_len
        self.maxLenIndex = self.minLenIndex = 0
        for pkt in pktList:
            if pkt.pload_len > self.maxLen:
                self.maxLen = pkt.pload_len
                self.maxLenIndex = i
            elif pkt.pload_len < self.minLen:
                self.minLen = pkt.pload_len
                self.minLenIndex = i
            total += pkt.pload_len
            i += 1

        self.avgLen = total / self.flowLen
        self.flowLenBytes = total

    def get_flag_counts(self, pktList):
        for pkt in pktList:
            flags = pkt.get_flags()
            if "F" in flags:
                self.finFlags += 1
            if "S" in flags:
                self.synFlags += 1
            if "R" in flags:
                self.rstFlags += 1
            if "P" in flags:
                self.pshFlags += 1
            if "A" in flags:
                self.ackFlags += 1
            if "U" in flags:
                self.urgFlags += 1
            if "E" in flags:
                self.eceFlags += 1
            if "C" in flags:
                self.cweFlags += 1


    def getStdLen(self, pktList):
        if len(pktList) < 2:
            # print("1 pkt in flow...stddev = 0")
            self.stdLen = 0
            return

        self.stdLen = stdev(pkt.pload_len for pkt in pktList)
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
        if self.flowLen == 1:
            self.minIA = self.maxIA = self.avgIA = self.stdIA = 0
            return
        if self.flowLen == 2:
            self.minIA = self.maxIA = self.avgIA = pktList[1].ts - pktList[0].ts
            self.stdIA = 0
            return

        total = 0
        iterable = iter(pktList)
        prev = next(iterable)
        self.minIA = prev.ts
        index = 0
        for pkt in iterable:
            diff = pkt.ts - prev.ts
            # print("diff: {}".format(diff))
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
                # print(pkt)
                # print(index)
            index += 1
        self.avgIA = total / (self.flowLen - 1)

    def getStdIA(self, pktList):
        if self.flowLen <= 2:
            self.stdIA = 0
        else:
            self.stdIA = stdev([j.ts - i.ts for i,j in zip(pktList[:-1], pktList[1:])])

    def getFlowDuration(self, pktList, biPktList):
        if not biPktList:
            if len(pktList) <= 1:
                self.flowDuration = 0
                return 0
            else:
                self.flowDuration = pktList[len(pktList) - 1].ts - pktList[0].ts
        else:
            if biPktList[len(biPktList) - 1].ts > pktList[len(pktList) - 1].ts: # biPkt is end of flow
                endts = biPktList[len(biPktList) - 1].ts
            else:
                endts = pktList[len(pktList) - 1].ts
            if biPktList[0].ts < pktList[0].ts:                                 # biPkt is beginning of flow
                startts = biPktList[0].ts
            else:
                startts = pktList[0].ts

            self.flowDuration = endts - startts
        return self.flowDuration


class FlowTable:
    def __init__(self):               # list is our config list
        # have tables as all caps (and acronyms)
        self.FT = {}
        self.timeout_count = {} # count # of flow timeouts
        # self.filter = filter

    def procPkt(self, pkt, transFlow):
        self.addFlow(pkt, transFlow)

    def addFlow(self, pkt, transFlow):
        if pkt.flow_tuple[0] == 6:
            flow_tuple = pkt.flow_tuple
        elif pkt.flow_tuple[0] == 17:
            flow_tuple = pkt.flow_tuple[:-1]
        else:
            print("unknown proto...exiting")
            exit(-1)

        # print("FLOW TUPLE: {}".format(flow_tuple))
        # timeout_count manages flows with same 5-tuples but have timed out
        if flow_tuple in self.timeout_count:
            FK = (flow_tuple, self.timeout_count[flow_tuple])
        else:
            self.timeout_count[flow_tuple] = 0
            self.timeout_count[pkt.biflow_tuple] = 0        # if either direction of flow ends, new flows created for both directions
            FK = (flow_tuple, self.timeout_count[flow_tuple])

        # print(FK)
        if FK not in self.FT:
            timeout = self.timeout_count[flow_tuple]
            self.FT[FK] = Flow(pkt.flow_tuple, pkt.ts, timeout) # add pkt with start time
            # self.setProcFlag(FK, transFlow)
            # self.FT[FK].addPkt(pkt)
        elif pkt.ts - self.FT[FK].flowStartTime > FLOWTIMEOUT:  # watch for flow timeout
            self.FT[FK].flowEndTime = pkt.ts
            self.timeout_count[flow_tuple] += 1
            self.timeout_count[pkt.biflow_tuple] += 1    # if either direction of flow ends, new flows created for both directions
            if self.timeout_count[flow_tuple] != self.timeout_count[pkt.biflow_tuple]:
                print("ERROR in flowtimeout: biflow timeout # != flow timeout #")
                exit(-1)
            # print("len flow before timeout: {}".format(len(self.FT[FK].pkts)))
            # print("TO pkt.ts: {}".format(pkt.ts))
            FK = (flow_tuple, self.timeout_count[flow_tuple])
            # print("Flow timeout! --> {}".format(FK))
            timeout = self.timeout_count[flow_tuple]
            self.FT[FK] = Flow(pkt.flow_tuple, pkt.ts, timeout)
            # self.setProcFlag(FK, transFlow)
            # self.FT[FK].addPkt(pkt)

        elif pkt.check_FIN():
            # print("FIN flag!")
            # print("fin pkt (ts): {}".format(pkt.ts))
            # self.setProcFlag(FK, transFlow)
            # self.FT[FK].addPkt(pkt)
            self.timeout_count[flow_tuple] += 1
            self.timeout_count[pkt.biflow_tuple] += 1        # if either direction of flow ends, new flows created for both directions
            self.FT[FK].end_fin = True
            self.FT[FK].flowEndTime = pkt.ts
            if self.timeout_count[flow_tuple] != self.timeout_count[pkt.biflow_tuple]:
                print("ERROR in fin flag: biflow timeout # != flow timeout #")
                exit(-1)

        self.setProcFlag(FK, transFlow)

        # if FK == ((6, '172.217.2.4', 443, '10.201.73.154', 60043), 0) or FK == ((6, '172.217.2.4', 443, '10.201.73.154', 60043), 1):
        #     print(pkt.ts, FK)
        self.FT[FK].addPkt(pkt)


    def setProcFlag(self, FK, transFlow):
        if transFlow == "Trans":
            self.FT[FK].procFlag = True
        elif transFlow == "NoTrans":
            self.FT[FK].procFlag = False
        else:
            print("ERROR: Invalid string")
            exit(-1)

    def evictFlow(self):
        print("timeout reached.  evict flow")

class FlowFilter:
    def __init__(self, list): #TODO: this list needs to be the global config_file
        self.tuple_set = set(list) # convert dict of flows to set (aka left with just the dict keys)
        self.tuple_set_no_timeout = set()
        # self.tuple_set_string = set()
        # print(self.tuple_set)
        for k in self.tuple_set:
            self.tuple_set_no_timeout.add(k[0])
            # self.tuple_set_string.add(str(k))
        # print(self.tuple_set_no_timeout)

    def needsTrans(self, pkt_tuple):
        #print(self.tuple_set)
        #print(pkt_5_tuple)
        biTuple = None
        if pkt_tuple[0] == 6: # TCP.  need bituple
            biTuple = (pkt_tuple[0], pkt_tuple[3], pkt_tuple[4], pkt_tuple[1], pkt_tuple[2])
        elif pkt_tuple[0] == 17:
            biTuple = (pkt_tuple[0], pkt_tuple[3], pkt_tuple[4], pkt_tuple[1])
            pkt_tuple = pkt_tuple[:-1]

        #pkt needs to be a TransPkt type
        if pkt_tuple in self.tuple_set_no_timeout:
            # print(pkt_tuple)
            return "Trans"
            # add and transform flag = true
        elif biTuple and biTuple in self.tuple_set_no_timeout:  # need this to ensure biflow is in flow table if flow needs transformation
            # print("bituple!")
            return "NoTrans"
        else:
            return False
            # don't add
        #     return True
        # return False