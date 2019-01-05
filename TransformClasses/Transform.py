import copy
from FlowTable import FlowTable
import numpy as np
from scipy.stats import truncnorm

def get_truncnorm(mean=0, sd=1, low=0, upp=10):
    return truncnorm((low - mean) / sd, (upp - mean) / sd, loc=mean, scale=sd)

MAX_PKT_LOOPS = 4
MAX_FRAME_SIZE = 3000

class Transform:
    def __init__(self, flowObj, config):
        self.flow = flowObj
        self.config = config
        #self.pktsToRemove = []

    def Process(self):
        raise NotImplementedError()


class TransPktLens(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        print("Creating new TransPktLens Object")

    def Process(self):
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        print(self.config)
        print(self.flow.flowStats)
        #self.testPktSplit()

        #self.mergePkt(self.flow.pkts[9], self.flow.pkts[10])
        #print(self.flow.pkts[10])
        #self.splitPkt(self.flow.pkts[10])
        #self.flow.pkts.sort()
        #self.flow.calcPktLenStats()

        # TODO: uncomment!  This does the pkt length manipulation
        # if self.flow.flowStats.avgLen < self.config["pktLens"]["avg"]:
        #     self.mergeLooper()
        # elif self.flow.flowStats.avgLen > self.config["pktLens"]["avg"]:
        #     self.splitLooper()

        """
        i=0
        while pkt len avg < target_avg
            merge pkt[i] and pkt[i+1]
            i++
            calcPktLenStats
        
        i=0
        while pkt len avg > target_avg
            split pkt[i]
            i += 2
            
        Split with a percentage of pkt to split?
        while std < target_std:
            find pkt.len closest to std:
                split pkt
                
        while std > target_std and pkt len avg > target avg:
            find pkt.len max:
                split pkt
        """

    def mergeLooper(self):
        i = totalLoops = 0
        # MERGE PACKETS
        while self.flow.flowStats.avgLen < self.config["pktLens"]["avg"]:
            if i + 1 == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    print("Reached max pkt loops, can't merge more pkts.  avg still < target avg")
                    print("i: {}".format(i))
                    break
                i = 0
                totalLoops += 1
                continue
            if self.flow.pkts[i].frame_len + self.flow.pkts[i + 1].frame_len >= MAX_FRAME_SIZE:
                i += 1
            else:
                if self.mergePkt(self.flow.pkts[i], self.flow.pkts[i + 1]):
                    self.flow.calcPktLenStats()
                else:
                    i += 1

    def splitLooper(self):
        i = totalLoops = 0
        # SPLIT PACKETS
        while self.flow.flowStats.avgLen > self.config["pktLens"]["avg"]:
            if i == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    print("Reached max pkt loops, can't split more pkts.  avg still > target avg")
                    print("i: {}".format(i))
                    break
                i = 0
                totalLoops += 1
                continue
            self.splitPkt(self.flow.pkts[i], i)
            self.flow.calcPktLenStats()
            i += 2

    def mergePkt(self, pkt, npkt):
        if pkt.http_pload and npkt.http_pload:# and (pkt.tcp_flags == npkt.tcp_flags): # make sure both pkts have payload and same flags
            print("prePKT: {}".format(pkt))
            print("preNPKT: {}".format(npkt))

            pkt.http_pload += npkt.http_pload
            pkt.ip_len = pkt.ip_len + len(npkt.http_pload)

            print("postPKT: {}".format(pkt))
            print("postNPKT: {}".format(npkt))

            self.flow.pkts.remove(npkt)
            return True
            #self.pktsToRemove.append(npkt)
        else:
            print("CAN'T MERGE PACKETS")
            return False

    def splitPkt(self, pkt, index):
        dupPkt = copy.deepcopy(pkt)
        oldPktLen = pkt.frame_len

        if pkt.http_pload:
            self.splitPayload(pkt, dupPkt)
            print("split payload")
        else:
            self.fixACKnum(pkt, dupPkt)
            print("split ack")

        # update IP ID
        dupPkt.ip_id += 1  # TODO: increment ipID (this will need to be adjusted at end of flow processing)
        self.flow.pkts.insert(index + 1, dupPkt)
        #self.flow.addPkt(dupPkt)
        # self.flow.incSplitLenStats(oldPktLen, pkt.frame_len, dupPkt.frame_len)

        #return dupPkt

    def splitPayload(self, pkt, dupPkt):
        len_payload = len(pkt.http_pload)
        ip_hdr_len = pkt.ip_len - len_payload
        dupPkt.http_pload = pkt.http_pload[len_payload // 2:]
        pkt.http_pload = pkt.http_pload[:len_payload // 2]

        pkt.ip_len = ip_hdr_len + len(pkt.http_pload)
        dupPkt.ip_len = ip_hdr_len + len(pkt.http_pload)

        dupPkt.seq_num += len(pkt.http_pload)

    def fixACKnum(self, pkt, dupPkt):
        biPkt = self.getMostRecentBiPkt(dupPkt)
        if biPkt:
            if not biPkt.http_pload:
                print("ERROR: ACKing an ACK.  uh oh!  biPkt should have a payload!")
                exit(-1)
            pkt.ack_num -= len(biPkt.http_pload) // 2

    # Find the closest biPkt to dupPkt that has payload w/o storing a bunch of pkts
    # TODO (low): optimize to do O(log n) search since biPkt list is sorted
    def getMostRecentBiPkt(self, pkt):
        flag = False
        biPkt = self.flow.biPkts[len(self.flow.biPkts)-1]
        for biPktObj in reversed(self.flow.biPkts):
            if biPktObj.ts < pkt.ts and biPktObj.http_pload:
                flag = True
                biPkt = biPktObj
                break
        if flag:
            return biPkt
        else:
            return flag

    def testPktSplit(self):
        print(self.flow.flowStats)
        newPkts = []
        for p in self.flow.pkts:
            newPkts.append(self.splitPkt(p))
        self.flow.pkts += newPkts
        self.flow.pkts.sort()
        # self.splitPkt(self.flow.pkts[17])
        # print("Transforming Pkt Lengths on these pkts: {}".format(self.flow))

    # def removePkts(self):
    #     for pkt in self.flow.pkts

class TransIATimes(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        print("Creating new TransIATimes Object")

    def Process(self):
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        #TODO: make sure lenStats are updated before this section!
        print("Transforming IA Times on these pkts: {}".format(self.flow))

        self.avgStdIATimes()
        self.flow.calcPktIAStats()

    def avgStdIATimes(self):
        targ_avg = self.config["iaTimes"]["avg"]
        targ_std = self.config["iaTimes"]["stddev"]
        print(targ_std)
        #i = 0
        t0 = self.flow.pkts[0].ts
        self.flow.pkts[self.flow.flowStats.flowLen - 1].ts = targ_avg * (self.flow.flowStats.flowLen - 1) + t0 # set last pkt ts
        tn = self.flow.pkts[self.flow.flowStats.flowLen - 1].ts
        print(t0, tn)
        print(tn-t0)

        X = get_truncnorm(targ_avg, targ_std, 0, tn-t0)
        X = X.rvs(self.flow.flowStats.flowLen - 2) # -2 since already have t0 and tn in place
        X.sort()
        for i in range(1, self.flow.flowStats.flowLen-1):
            self.flow.pkts[i].ts = t0 + X[i-1]
            i += 1
        # for pkt in self.flow.pkts:
        #     pkt.ts = t0 + i
        print(X)
        print(np.std(X))


















