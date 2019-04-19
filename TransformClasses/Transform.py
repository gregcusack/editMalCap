import copy
from FlowTable import FlowTable
import numpy as np
from scipy.stats import truncnorm
from itertools import islice
from math import ceil
from random import randint, uniform
from scapy.all import *
import warnings

ETH_HDR_LEN = 14

def get_truncnorm(mean=0, sd=1, low=0, upp=10):
    return truncnorm((low - mean) / sd, (upp - mean) / sd, loc=mean, scale=sd)

MAX_PKT_LOOPS = 4
MAX_FRAME_SIZE = 3000

class Transform:
    def __init__(self, flowObj, config):
        self.flow = flowObj
        self.config = config
        print("transform create")
        #self.pktsToRemove = []

    def Process(self):
        raise NotImplementedError()

class LengthTransform(Transform):
    def __init__(self, flowObj, config, biFlowFlag):
        Transform.__init__(self, flowObj, config)
        self.biFlowFlag = biFlowFlag
        print("Creating new LengthTransform Object")

    def Process(self):
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        print("LengthTransform Process()")
        print("flow: {}".format(self.flow))

        if "Tot Fwd Pkts" in self.config:
            self.fixTotFwdPkts()

    def fixTotFwdPkts(self):
        print("fixing Tot Fwd Pkts")
        og_tot_fwd_pkts = self.config["Tot Fwd Pkts"]["og"]
        adv_tot_fwd_pkts = self.config["Tot Fwd Pkts"]["adv"]

        if og_tot_fwd_pkts == adv_tot_fwd_pkts:
            print("og Tot Fwd Pkts == adv Tot Fwd Pkts")
            return

        if og_tot_fwd_pkts < adv_tot_fwd_pkts:
            self.splitLooper(og_tot_fwd_pkts, adv_tot_fwd_pkts)
        else:
            self.mergeLooper(og_tot_fwd_pkts, adv_tot_fwd_pkts)

    def mergeLooper(self, og_tot_fwd_pkts, adv_tot_fwd_pkts):
        i = totalLoops = 0
        MaxPktLen = self.config["pktLens"]["max"]
        # MERGE PACKETS
        while self.flow.flowStats.avgLen < self.config["pktLens"]["avg"]:
            if i + 1 == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    print("Reached max pkt loops, can't merge more pkts.  avg still < target avg")
                    # print("i: {}".format(i))
                    break
                i = 0
                totalLoops += 1
                continue
            # print("flags: {}".format(self.flow.pkts[i].get_flags()))
            if self.flow.pkts[i].pload_len and self.flow.pkts[i + 1].pload_len:
                if self.flow.pkts[i].pload_len + self.flow.pkts[i + 1].pload_len >= MaxPktLen:
                    i += 1
                elif self.mergePkt(self.flow.pkts[i], self.flow.pkts[i + 1]):
                    self.flow.calcPktLenStats()
                else:
                    i += 1
            else:
                i += 1


    def splitLooper(self, og_tot_fwd_pkts, adv_tot_fwd_pkts):
        avgPktLen = self.config["pktLens"]["avg"]
        try:
            maxPktLen = self.config["pktLens"]["max"]
        except KeyError:
            maxPktLen = 1418
        try:
            minPktLen = self.config["pktLens"]["min"]
        except KeyError:
            minPktLen = 0

        i = totalLoops = 0
        # SPLIT PACKETS, start with packets > maxPktLen set by user
        while self.flow.flowStats.flowLen < adv_tot_fwd_pkts:# and self.flow.flowStats.maxLen > maxPktLen:
            if i == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    # print("Reached max pkt loops, can't split more pkts.  max pkt len too small")
                    break
                i = 0
                totalLoops += 1
                continue
            if self.flow.pkts[i].pload_len > 0 and self.flow.pkts[i].pload_len > maxPktLen:
                if self.flow.pkts[i].pload_len // 2 < minPktLen:        # don't split packet if goes below min pkt len
                    i += 1
                    continue
                self.splitPkt(self.flow.pkts[i], i)
                self.flow.calcPktLenStats()
                i += 2
            else:
                i += 1

        # if still haven't reached avg len.  Begin splitting all other packets with payload
        pktsLessThanMinPktLen = 0
        minPktFlag = False
        if minPktLen > 0:
            minPktFlag = True
        i = totalLoops = 0
        while self.flow.flowStats.avgLen > avgPktLen: # case where max pktLen < config max pktLen but avg pktLen is still too large
            if minPktLen and self.flow.flowStats.flowLen <= pktsLessThanMinPktLen:
                warnings.warn("Min Packet Length set by user too small!")
                warnings.warn("Can't converge on avg. packet length.  Ignorning min pkt length requirement")
                minPktFlag = False
            if i == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    warnings.warn("Reached max pkt loops, can't split more pkts.  avg still > target avg.  NOT CONVERGED")
                    break
                i = 0
                totalLoops += 1
                pktsLessThanMinPktLen = 0
                continue
            if minPktFlag and self.flow.pkts[i].pload_len // 2 < minPktLen:  # don't split packet if goes below min pkt len
                i += 1
                pktsLessThanMinPktLen += 1
                continue
            if self.flow.pkts[i].pload_len > 0:
                self.splitPkt(self.flow.pkts[i], i)
                self.flow.calcPktLenStats()
                i += 2
            else:
                i += 1

        # NOT GOING TO SPLIT ACKS. uncomment if want to split acks
        # # after trying to split payloads, we're now going to allow the splitting acks (last resort)
        # i = totalLoops = 0
        # while self.flow.flowStats.avgLen > avgPktLen:  # case where max pktLen < config max pktLen but avg pktLen is still too large
        #     if i == self.flow.flowStats.flowLen:
        #         if totalLoops == MAX_PKT_LOOPS:
        #             print("Reached max pkt loops, can't split more pkts.  avg still > target avg.  NOT CONVERGED")
        #             # print("i: {}".format(i))
        #             break
        #         i = 0
        #         totalLoops += 1
        #         continue
        #     self.splitPkt(self.flow.pkts[i], i)
        #     self.flow.calcPktLenStats()
        #     i += 2

    def mergePkt(self, pkt, npkt):
        if pkt.http_pload and npkt.http_pload:# and (pkt.tcp_flags == npkt.tcp_flags): # make sure both pkts have payload and same flags
            # print("prePKT: {}".format(pkt))
            # print("preNPKT: {}".format(npkt))

            pkt.http_pload += npkt.http_pload
            pkt.ip_len = pkt.ip_len + len(npkt.http_pload)

            # print("postPKT: {}".format(pkt))
            # print("postNPKT: {}".format(npkt))

            self.flow.pkts.remove(npkt)
            return True
            # self.pktsToRemove.append(npkt)
        else:
            # print("CAN'T MERGE PACKETS")
            return False

    def splitPkt(self, pkt, index):
        dupPkt = copy.deepcopy(pkt)
        oldPktLen = pkt.frame_len

        if pkt.http_pload:
            self.splitPayload(pkt, dupPkt)
            #print("split payload")
        else:
            self.fixACKnum(pkt, dupPkt)
            #print("split ack")

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
        dupPkt.ip_len = ip_hdr_len + len(dupPkt.http_pload)

        dupPkt.seq_num += len(pkt.http_pload)

    def fixACKnum(self, pkt, dupPkt):
        biPkt = self.getMostRecentBiPkt(dupPkt)
        if biPkt:
            if not biPkt.http_pload:
                print("ERROR: ACKing an ACK.  uh oh!  biPkt should have a payload!")
                exit(-1)
            pkt.ackSplitCount += 1
            dupPkt.ackSplitCount += 1
            pkt.ack_num -= len(biPkt.http_pload) // pkt.ackSplitCount + 1 # add plus one to avoid duplicate ack

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



class TimeTransform(Transform):
    def __init__(self, flowObj, config, biFlowFlag):
        Transform.__init__(self, flowObj, config)
        self.biFlowFlag = biFlowFlag
        print("creating new TimeTransform Object")

    def Process(self):
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        print("TimeTransform Process()")

class FlagTransform(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        print("Creating new FlagTransform Object")

    def Process(self):
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        print("FlagTransform Process()")



####################################################
####################################################
####################################################
####################################################


class TransPktLens(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        # print("Creating new TransPktLens Object")

    def Process(self):
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        if self.flow.flowStats.flowLenBytes == 0:
            print("all ptks have payload == 0.  returning...")
            return
        print("# of pkts in flow: {}".format(self.flow.flowStats.flowLen))
        # print("Transforming pkt lengths on these pkts: {}".format(self.flow))
        # print("pre len trans: {}".format(self.flow.flowStats))

        #print(self.config)
        #print(self.flow.flowStats)
        #self.testPktSplit()

        # TODO: uncomment!  This does the pkt length manipulation
        if self.flow.flowStats.avgLen < self.config["pktLens"]["avg"]:
            self.mergeLooper()
        elif self.flow.flowStats.avgLen > self.config["pktLens"]["avg"]:
            self.splitLooper()

        print("post len trans: {}".format(self.flow.flowStats))

    def mergeLooper(self):
        i = totalLoops = 0
        MaxPktLen = self.config["pktLens"]["max"]
        # MERGE PACKETS
        while self.flow.flowStats.avgLen < self.config["pktLens"]["avg"]:
            if i + 1 == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    print("Reached max pkt loops, can't merge more pkts.  avg still < target avg")
                    # print("i: {}".format(i))
                    break
                i = 0
                totalLoops += 1
                continue
            # print("flags: {}".format(self.flow.pkts[i].get_flags()))
            if self.flow.pkts[i].pload_len and self.flow.pkts[i + 1].pload_len:
                if self.flow.pkts[i].pload_len + self.flow.pkts[i + 1].pload_len >= MaxPktLen:
                    i += 1
                elif self.mergePkt(self.flow.pkts[i], self.flow.pkts[i + 1]):
                    self.flow.calcPktLenStats()
                else:
                    i += 1
            else:
                i += 1


    def splitLooper(self):
        avgPktLen = self.config["pktLens"]["avg"]
        try:
            maxPktLen = self.config["pktLens"]["max"]
        except KeyError:
            maxPktLen = 1418
        try:
            minPktLen = self.config["pktLens"]["min"]
        except KeyError:
            minPktLen = 0

        i = totalLoops = 0
        # SPLIT PACKETS, start with packets > maxPktLen set by user
        while self.flow.flowStats.avgLen > avgPktLen and self.flow.flowStats.maxLen > maxPktLen:
            if i == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    # print("Reached max pkt loops, can't split more pkts.  max pkt len too small")
                    break
                i = 0
                totalLoops += 1
                continue
            if self.flow.pkts[i].pload_len > 0 and self.flow.pkts[i].pload_len > maxPktLen:
                if self.flow.pkts[i].pload_len // 2 < minPktLen:        # don't split packet if goes below min pkt len
                    i += 1
                    continue
                self.splitPkt(self.flow.pkts[i], i)
                self.flow.calcPktLenStats()
                i += 2
            else:
                i += 1

        # if still haven't reached avg len.  Begin splitting all other packets with payload
        pktsLessThanMinPktLen = 0
        minPktFlag = False
        if minPktLen > 0:
            minPktFlag = True
        i = totalLoops = 0
        while self.flow.flowStats.avgLen > avgPktLen: # case where max pktLen < config max pktLen but avg pktLen is still too large
            if minPktLen and self.flow.flowStats.flowLen <= pktsLessThanMinPktLen:
                warnings.warn("Min Packet Length set by user too small!")
                warnings.warn("Can't converge on avg. packet length.  Ignorning min pkt length requirement")
                minPktFlag = False
            if i == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    warnings.warn("Reached max pkt loops, can't split more pkts.  avg still > target avg.  NOT CONVERGED")
                    break
                i = 0
                totalLoops += 1
                pktsLessThanMinPktLen = 0
                continue
            if minPktFlag and self.flow.pkts[i].pload_len // 2 < minPktLen:  # don't split packet if goes below min pkt len
                i += 1
                pktsLessThanMinPktLen += 1
                continue
            if self.flow.pkts[i].pload_len > 0:
                self.splitPkt(self.flow.pkts[i], i)
                self.flow.calcPktLenStats()
                i += 2
            else:
                i += 1

        # NOT GOING TO SPLIT ACKS. uncomment if want to split acks
        # # after trying to split payloads, we're now going to allow the splitting acks (last resort)
        # i = totalLoops = 0
        # while self.flow.flowStats.avgLen > avgPktLen:  # case where max pktLen < config max pktLen but avg pktLen is still too large
        #     if i == self.flow.flowStats.flowLen:
        #         if totalLoops == MAX_PKT_LOOPS:
        #             print("Reached max pkt loops, can't split more pkts.  avg still > target avg.  NOT CONVERGED")
        #             # print("i: {}".format(i))
        #             break
        #         i = 0
        #         totalLoops += 1
        #         continue
        #     self.splitPkt(self.flow.pkts[i], i)
        #     self.flow.calcPktLenStats()
        #     i += 2

    def mergePkt(self, pkt, npkt):
        if pkt.http_pload and npkt.http_pload:# and (pkt.tcp_flags == npkt.tcp_flags): # make sure both pkts have payload and same flags
            # print("prePKT: {}".format(pkt))
            # print("preNPKT: {}".format(npkt))

            pkt.http_pload += npkt.http_pload
            pkt.ip_len = pkt.ip_len + len(npkt.http_pload)

            # print("postPKT: {}".format(pkt))
            # print("postNPKT: {}".format(npkt))

            self.flow.pkts.remove(npkt)
            return True
            # self.pktsToRemove.append(npkt)
        else:
            # print("CAN'T MERGE PACKETS")
            return False

    def splitPkt(self, pkt, index):
        dupPkt = copy.deepcopy(pkt)
        oldPktLen = pkt.frame_len

        if pkt.http_pload:
            self.splitPayload(pkt, dupPkt)
            #print("split payload")
        else:
            self.fixACKnum(pkt, dupPkt)
            #print("split ack")

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
        dupPkt.ip_len = ip_hdr_len + len(dupPkt.http_pload)

        dupPkt.seq_num += len(pkt.http_pload)

    def fixACKnum(self, pkt, dupPkt):
        biPkt = self.getMostRecentBiPkt(dupPkt)
        if biPkt:
            if not biPkt.http_pload:
                print("ERROR: ACKing an ACK.  uh oh!  biPkt should have a payload!")
                exit(-1)
            pkt.ackSplitCount += 1
            dupPkt.ackSplitCount += 1
            pkt.ack_num -= len(biPkt.http_pload) // pkt.ackSplitCount + 1 # add plus one to avoid duplicate ack 

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

class TransIATimes(Transform):
    def __init__(self, flowObj, config, biFlowFlag):
        Transform.__init__(self, flowObj, config)
        self.biFlowFlag = biFlowFlag
        print("Creating new TransIATimes Object")

    def Process(self):
        # self.flow.calcPktLenStats()
        # self.flow.calcPktIAStats()
        #TODO: make sure lenStats are updated before this section!
        print("Transforming IA Times on these pkts: {}".format(self.flow))

        # check if there are pkts going in opposite direction
        if self.biFlowFlag:
            self.flow.getDiffs()
            # print("\nDone getting diffs")
            self.avgStdIATimes()
            # print("Done updating iatimes")
            self.updateBiTS()
            self.flow.getDiffs()                    # once it works I think you can delete this
        else:
            self.avgStdIATimes()

        # self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        #print(self.flow.flowStats)
        #self.updateBiTS()

    def avgStdIATimes(self):
        targ_avg = self.config["iaTimes"]["avg"]
        targ_std = self.config["iaTimes"]["stddev"]
        if "max" in self.config["iaTimes"]:
            targ_max = self.config["iaTimes"]["max"]
        else:
            targ_max = self.flow.flowStats.maxIA

        # if "min" in self.config["iaTimes"]:
        #     targ_min = self.config["iaTimes"]["min"]
        # else:
        #     targ_min = 0

        targ_min = 0

        X = get_truncnorm(targ_avg, targ_std, targ_min, targ_max)  #lower bound "min" in config, upper bound "max" if exists, else maxIA
        X = X.rvs(self.flow.flowStats.flowLen - 1)  # -1 since already have t0 in place

        # Best effort reconstruction
        prev = self.flow.pkts[0].ts
        for i in range(1, self.flow.flowStats.flowLen):
            # print(X[i-1])
            self.flow.pkts[i].ts = prev + X[i-1]
            prev = self.flow.pkts[i].ts
            i += 1

        # print("pkts 0,1: {}, {}".format(self.flow.pkts[0].ts, self.flow.pkts[1].ts))

    def updateBiTS(self):
        i = j = k = 0
        prev_ts = None
        prev_dir = self.flow.diffs[0][0]                # TODO: make diff list a list of namedtuples!
        if prev_dir == "F":
            prev_ts = self.flow.pkts[0].ts
            i += 1
        elif prev_dir == "B":
            prev_ts = self.flow.biPkts[0].ts
            j += 1
        elif prev_dir == "S":
            print("ERROR? FLOW STARTS AT SAME TIME?!?!?! in updateBiTS()")
            print("Exiting...")
            exit(-1)
            # i += 1
            # j += 1
        else:
            print("ERROR! updateBiTS() error!")
            exit(-1)
        k += 1

        # print("i: {}, j: {}, k: {}".format(i,j,k))

        lastFDiffIndex = None

        while k < len(self.flow.diffs):
        #for dir in range(1,len(self.flow.diffs)):
            # print("k: {}".format(k))
            # print("sup")
            # print(self.flow.diffs)
            # print(self.flow.diffs[k][0])
            # print("ts diff: {}".format(self.flow.pkts[1].ts - self.flow.pkts[0].ts))
            if self.flow.diffs[k][0] == "B":
                count = 0
                bis = []
                while k < len(self.flow.diffs) and self.flow.diffs[k][0] == "B":
                    # print("k: {}".format(k))
                    # print(self.flow.)
                    # print("b looping")
                    count += 1
                    bis.append(j)
                    j += 1
                    k += 1
                # print(count)
                # if count == 0:
                #     count == 1
                # print(bis)
                # print("i: {}".format(i))
                # print("pkts: {}".format(self.flow.pkts))
                # TODO: if B is last pkt, then no step needed.  take all b packets and add
                if k != len(self.flow.diffs):   # at least one more F in biflow
                    step = (self.flow.pkts[i].ts - self.flow.pkts[i-1].ts) / count
                    # print("step: {}".format(step))
                    #print(count)
                    m = 0
                    for n in bis:
                        #print("n: {}".format(n))
                        self.flow.biPkts[n].ts = self.flow.pkts[i-1].ts + step * m + step / 2
                        m += 1
                else: # signifies B is last pkt
                    if self.flow.pkts[i - 1].ts > self.flow.biPkts[bis[0]].ts:      # F pkt moved ahead of B after IAT trans
                        # TODO: move all bipkts whose index is in bis[] on other side of last F
                        # B0.ts = last_F.ts + (B0 - last_F.ts)
                        # B0.ts - last_F.ts is stored in diffs at
                        # print("need to move B pkts on other side of the last F")
                        p_ts = self.flow.pkts[i - 1].ts
                        for n in bis:
                            # print("lastfDiffIndex: {}".format(lastFDiffIndex))
                            self.flow.biPkts[n].ts = p_ts + self.flow.diffs[lastFDiffIndex][1]
                            p_ts = self.flow.biPkts[n].ts
                            lastFDiffIndex += 1
                    else:
                        print("F didn't move to other side of B, so think we're good???")
                # print("len bis[]: {}".format(len(bis)))

            elif self.flow.diffs[k][0] == "F":
                prev_ts = self.flow.pkts[i].ts
                i += 1
                k += 1
                if i >= len(self.flow.pkts):
                    lastFDiffIndex = k
            else:
                prev_ts = self.flow.pkts[i].ts
                print("F AND B AT SAME TIME!")
                i += 1
                j += 1
                k += 1

class TransDistUDP(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        # print("Creating new TransSplitPkts Object")

    def Process(self):
        print("Process TransDistUDP")
        self.flow.calcPktLenStats()
        self.split_flow()

    def split_flow(self):
        numFlows = self.config["numFlows"]
        # print(self.flow.flowStats.flowLen)
        pktsPerSplitFlow = ceil(self.flow.flowStats.flowLen / numFlows)
        flowKeys = []
        flowKeys.append(self.flow.flowKey)
        # print(flowKeys)
        self.genNewFlowKeys(numFlows, flowKeys)
        # print(flowKeys)
        self.updatePktFlowKeys(flowKeys, pktsPerSplitFlow)

    def genNewFlowKeys(self, numFlows, flowKeys):
        newIPs = []
        newPorts = []
        proto = self.flow.flowKey[0]
        IPsrc = self.flow.flowKey[1]
        portSrc = self.flow.flowKey[2]
        IPdst = self.flow.flowKey[3]

        IPsrc_split = IPsrc.split(".", 3)
        IPsrcSubnet0 = IPsrc_split[0]
        IPsrcSubnet8 = IPsrc_split[1]
        IPsrcSubnet16 = IPsrc_split[2]
        IPsrcSubnet24 = IPsrc_split[3]

        for i in range(numFlows - 1):
            flag = True
            while flag:
                IP24_prime = randint(0, 255)
                if IP24_prime != int(IPsrcSubnet24) and IP24_prime not in newIPs:
                    flag = False
                    newIPs.append(IP24_prime)
                    #print(IP24_prime)
                IPsrc_prime = IPsrcSubnet0 + "." + IPsrcSubnet8 + "." + IPsrcSubnet16 + "." + str(IP24_prime)
                #print(IPsrc_prime)
            flag = True
            while flag:
                portSrc_prime = randint(0, 65535)
                if portSrc_prime != int(portSrc) and portSrc_prime not in newPorts:
                    flag = False
                    newPorts.append(portSrc_prime)
                    #print(portSrc_prime)
            flowKey_prime = (proto, IPsrc_prime, portSrc_prime, IPdst)
            #print(self.flow.flowKey)
            #print(flowKey_prime)
            flowKeys.append(flowKey_prime)
        return flowKeys

    def updatePktFlowKeys(self, flowKeys, pktsPerSplitFlow):
        current = pktCounter = 0
        indexCounter = 0
        # print("total pkts in flow: {}".format(len(self.flow.pkts)))
        for pkt in self.flow.pkts:
            pkt.pktSetUDPTuple(flowKeys[current])
            pktCounter += 1
            if pktCounter == pktsPerSplitFlow or pkt == self.flow.pkts[len(self.flow.pkts)-1]:
                pktCounter = 0
                current += 1
            indexCounter += 1



# class TransSplitPkts(Transform):
#     def __init__(self, flowObj, config):
#         Transform.__init__(self, flowObj, config)
#         print("Creating new TransSplitPkts Object")
#
#     def Process(self):
#         print("Process TransSplitPkts")
#         self.flow.calcPktLenStats()
#         self.flow.calcPktIAStats()
#         self.splitFlow()
#
#     def splitFlow(self):
#         numFlows = self.config["numFlows"]
#         pktsPerSplitFlow = ceil(self.flow.flowStats.flowLen / numFlows) #TODO: the floor() may cause rounding issues and result in lost pkts...
#         print("pkts per splitflow: {}".format(pktsPerSplitFlow))
#         flowKeys = []
#         timestamps = []
#         startPkts = []          # this holds indices of first pkt in each new splitFlow
#         flowKeys.append(self.flow.flowKey)
#         self.genNewFlowKeys(numFlows, flowKeys)
#         print("New Flow Keys: {}".format(flowKeys))
#
#         print(self.flow.pkts)
#         self.updatePktFlowKeys(flowKeys, pktsPerSplitFlow, timestamps, startPkts)
#         print(self.flow.pkts)
#         print(timestamps)
#
#         print(self.flow.biPkts)
#         self.updateBiPktFlowKeys(flowKeys, timestamps)
#         print(self.flow.biPkts)
#
#         print("start pkts: {}".format(startPkts))
#         print(flowKeys)
#
#         if self.flow.flowKey[0] == 6: # TODO: will also need to check if the attack requires this (slowloris does not, patator does)
#             print("TCP")
#             for i in range(numFlows-1):
#                 # Check cases where we split in the middle of a tcp 3way HS
#                 sFlag = saFlag = aFlag = True
#                 firstPkt = self.flow.pkts[startPkts[i]]
#                 if firstPkt.tcp_flags == "S":   # don't create 3wHS since already exists
#                     sFlag = saFlag = aFlag = False
#                 elif firstPkt.tcp_flags == "SA": # We just need to create a SYN flag to match the SA
#                     saFlag = aFlag = False
#                 elif startPkts[i]-1 != 0 and firstPkt.tcp_flags == "A" and self.flow.pkts[startPkts[i] - 1].tcp_flags == "SA":   # ack is from end of 2wHS
#                     aFlag = False # don't need to create ACK
#
#                 newSyn = newSynAck = None
#                 print("index to insert: {}".format(startPkts[i]))
#                 if sFlag:
#                     newSyn = self.createSYNPkt(firstPkt)
#                     self.flow.pkts.insert(startPkts[i], newSyn) # TODO: these are being inserted in the wrong spot
#                 # if saFlag:
#                 #     if newSyn == None:
#                 #         print("ERROR.  SA created without an S!  Bad!")
#                 #     newSynAck = self.createSYNACKPkt(firstPkt, newSyn)
#                 #     self.flow.pkts.insert(startPkts[i] - 1, newSynAck)
#                 # if aFlag:
#                 #     print("Creating ACK for 3wHS")
#
#         # TODO:
#         # 1) insert 3 way HS
#         # 2) insert fin-fin/ack
#         # 3) Delete original flow from table, load splitflows into flow table
#
#
#
#     def genNewFlowKeys(self, numFlows, flowKeys):
#         newIPs = []
#         newPorts = []
#         proto = self.flow.flowKey[0]
#         IPsrc = self.flow.flowKey[1]
#         portSrc = self.flow.flowKey[2]
#         IPdst = self.flow.flowKey[3]
#         portDst = self.flow.flowKey[4]
#
#         IPsrc_split = IPsrc.split(".", 3)
#         IPsrcSubnet0 = IPsrc_split[0]
#         IPsrcSubnet8 = IPsrc_split[1]
#         IPsrcSubnet16 = IPsrc_split[2]
#         IPsrcSubnet24 = IPsrc_split[3]
#
#         for i in range(numFlows - 1):
#             flag = True
#             while flag:
#                 IP24_prime = randint(0, 255)
#                 if IP24_prime != int(IPsrcSubnet24) and IP24_prime not in newIPs:
#                     flag = False
#                     newIPs.append(IP24_prime)
#                     #print(IP24_prime)
#                 IPsrc_prime = IPsrcSubnet0 + "." + IPsrcSubnet8 + "." + IPsrcSubnet16 + "." + str(IP24_prime)
#                 #print(IPsrc_prime)
#             flag = True
#             while flag:
#                 portSrc_prime = randint(0, 65535)
#                 if portSrc_prime != int(portSrc) and portSrc_prime not in newPorts:
#                     flag = False
#                     newPorts.append(portSrc_prime)
#                     #print(portSrc_prime)
#             flowKey_prime = (proto, IPsrc_prime, portSrc_prime, IPdst, portDst)
#             #print(self.flow.flowKey)
#             #print(flowKey_prime)
#             flowKeys.append(flowKey_prime)
#         return flowKeys
#
#     def updatePktFlowKeys(self, flowKeys, pktsPerSplitFlow, timestamps, startPkts):
#         ts0 = self.flow.pkts[0].ts
#         current = pktCounter = 0
#         indexCounter = 0
#         print("total pkts in flow: {}".format(len(self.flow.pkts)))
#         for pkt in self.flow.pkts:
#             # print(pkt.ts)
#
#             #pkt.flow_tuple = flowKeys[current]
#             pkt.pktSet5Tuple(flowKeys[current])
#             pktCounter += 1
#             #print(pktCounter)
#             if pktCounter == pktsPerSplitFlow or pkt == self.flow.pkts[len(self.flow.pkts)-1]:
#                 ts1 = pkt.ts
#                 pktCounter = 0
#                 timestamps.append((ts0, ts1))
#                 ts0 = ts1
#                 current += 1
#                 #print("#############################")
#                 if pkt != self.flow.pkts[len(self.flow.pkts) - 1]:
#                     startPkts.append(indexCounter + 1)
#             indexCounter += 1
#
#     def updateBiPktFlowKeys(self, flowKeys, timestamps):
#         splitFlowCounter = pktCounter = base = 0
#         for ts in timestamps:
#             for i in range(len(self.flow.biPkts) - 1):
#                 if base + pktCounter == len(self.flow.biPkts):
#                     break
#                 if self.flow.biPkts[base + pktCounter].ts > ts[0] and self.flow.biPkts[base + pktCounter].ts <= ts[1]:
#                     self.flow.biPkts[base + pktCounter].pktSet5Tuple((self.flow.biPkts[base + pktCounter].flow_tuple[0], self.flow.biPkts[base + pktCounter].flow_tuple[1], self.flow.biPkts[base + pktCounter].flow_tuple[2], flowKeys[splitFlowCounter][1], flowKeys[splitFlowCounter][2]))
#                 elif self.flow.biPkts[base + pktCounter].ts < ts[0]:
#                     pktCounter += 1
#                     continue
#                 else:
#                     # case where biPkts.ts > timestamps[1]
#                     base = base + pktCounter
#                     pktCounter = 0
#                     splitFlowCounter += 1
#                     break
#                 pktCounter += 1
#
#
#     def genTCPHandshake(self):
#         print("generating TCP Handshake")
#
#     def genFinConnection(self):
#         print("generating FIN -> Fin/ACK close connection")
#
#     def createSYNPkt(self, firstPkt):
#         print("createSYNPkt")
#         newPkt = copy.deepcopy(firstPkt)
#         length = None
#         if newPkt.http_pload:
#             length = len(newPkt.http_pload)
#             newPkt.seq_num = firstPkt.seq_num - length
#             newPkt.remove_payload()
#         else: # S, ACK, SA
#             print("NO PAYLOAD for createSYNPkt()")
#
#         #print(newPkt.printSummary())
#         newPkt.set_flags("S")
#         newPkt.ack_num = 0
#         newPkt.addSYNOptions()
#         #print(newPkt.printSummary())
#         newPkt.frame_len = newPkt.len()
#         newPkt.ip_len = newPkt.frame_len
#         #print(newPkt.len())
#
#         f_ts = firstPkt.ts
#         mid = f_ts - 0.01
#         min = mid - 0.005
#         max = mid + 0.005
#
#         newPkt.ts = random.uniform(min, max)
#         #print(newPkt.printShow())
#         #print(firstPkt)
#         return newPkt
#
#     def createSYNACKPkt(self, firstPkt, synPkt):
#         print("create syn ack")
#         print("FIRST_PKT ACK_NUM: {}".format(firstPkt.ack_num))
#
#         print(firstPkt.printShow())
#         saPkt = copy.deepcopy(synPkt)
#         if firstPkt.ack_num != 0:
#             saPkt.seq_num = firstPkt.ack_num - 1            # TODO: this is wrong.  I'm getting -1
#         else:
#             saPkt.seq_num = 0
#         saPkt.ack_num = synPkt.seq_num + 1
#         saPkt.set_flags("SA")
#
#         saPkt.addSYNACKOptions()
#
#         #print(saPkt.printShow())
#
#         saPkt.frame_len -= 4
#         saPkt.ip_len = saPkt.frame_len
#
#         sTS = synPkt.ts
#         fTS = firstPkt.ts
#         ts = (fTS - sTS) / 2
#         mid = sTS + ts
#         quarter = (mid - ts) / 2
#         min = sTS + quarter
#         max = mid + quarter
#         saPkt.ts = random.uniform(min, max)
#         print(saPkt.printShow())
#
#         return saPkt
#
#         #saPkt.frame_len = saPkt.len()
#         # saPkt.ip_len = saPkt.frame_len
#         #
#         #
#         # print(saPkt.ip_len)
#
#




















