import copy
from TransformClasses.Merger import Merger
from TransformClasses.Injector import Injector

MAX_PKT_LOOPS = 6
MAX_SPLIT_PKT = 10 #10 should work but just takes longer
MAX_FRAME_SIZE = 3000

class Splitter:
    def __init__(self, flowObj, config):
        self.flow = flowObj
        self.config = config

        self.og_tot_fwd_pkts = self.config["Tot Fwd Pkts"]["og"]
        self.adv_tot_fwd_pkts = self.config["Tot Fwd Pkts"]["adv"]

        self.og_fwd_pkt_len_max = self.config["Fwd Pkt Len Max"]["og"]
        self.adv_fwd_pkt_len_max = self.config["Fwd Pkt Len Max"]["adv"]
        self.og_fwd_pkt_len_min = self.config["Fwd Pkt Len Min"]["og"]
        self.adv_fwd_pkt_len_min = self.config["Fwd Pkt Len Min"]["adv"]

        self.injector = Injector(flowObj)

        # print("transform create")
        #self.pktsToRemove = []

    def split_max_lens_eq(self):
        print("split_max_lens_eq (og, adv): ({}, {})".format(self.og_tot_fwd_pkts, self.adv_tot_fwd_pkts))
        if self.flow.flowStats.maxLen == 0:
            print("max pkt length == 0.  Can't split.  Returning")
            return

        if self.split_looper_avoid_index(self.flow.flowStats.maxLenIndex):
            print("flow len correct and max pkt len correct!")
            return

        # can't converge, so split packet that == max_len
        if self.split_max_packet(): # totallen == adv_len but
            print("total_len == adv_len, now inject packet with max pkt len")
            self.injector.inject_one(self.flow.pkts[len(self.flow.pkts) - 1], self.adv_fwd_pkt_len_max)
        else:
            print("CAN'T CONVERGE!")

    def split_og_max_len_lt(self):                                        # index to store location of max packet
        # NOTE: we have not split any packets at this point
        index = self.create_max_packet_len()                # this means we have an index set and we have a packet that == adv_fwd_pkt_len_max
        if index != -1:
            if self.split_looper_avoid_index(index):         # if return true, then max lens are equal AND flow lens are equal
                print("split_og_max_len_lt success!")
                return
            else:                                           # didn't reach max length, so need to split the packet with length == max length
                print("split_og_max_len_lt not quite there.  split max pkt, then inject")
                self.split_max_packet()
                self.injector.inject_one(self.flow.pkts[len(self.flow.pkts) - 1], self.adv_fwd_pkt_len_max)
        else:                                               # no two packets sum to > adv_max_len, split all packets then inject
            if self.split_looper_all(True):                    # split all packets and tot_pkts == adv_tot_pkts
                print("Split success, still need to inject")
                self.injector.inject_one(self.flow.pkts[len(self.flow.pkts) - 1], self.adv_fwd_pkt_len_max)
            else:
                print("can't reach tot. # pkts.  inject to reach")
                self.injector.inject_many(self.flow.pkts[len(self.flow.pkts) - 1],
                                          self.adv_tot_fwd_pkts, self.adv_fwd_pkt_len_max, self.adv_fwd_pkt_len_min)

    def split_og_max_len_gt(self):
        if self.split_looper_start_with_max():     # totalpkts == adv_pkts
            print("total_pkts == adv_pkts")
            if self.flow.flowStats.maxLen > self.adv_fwd_pkt_len_max:
                print("after split max: tot_pkts == adv_pkts but maxLen still > adv_max_len, can't fix")
                return
            index = self.create_max_packet_len()
            if index != -1:
                print("able to create max packet!")
            else:
                print("tot_pkts == adv_pkts but can't reach max pkt len -- inject!")
                self.injector.inject_one(self.flow.pkts[len(self.flow.pkts) - 1], self.adv_fwd_pkt_len_max)
        else:                   # split rest of packets
            if self.split_looper_all(False):  # tot_pkt == adv_pkts
                if self.flow.flowStats.maxLen > self.adv_fwd_pkt_len_max:
                    print("after split all: tot_pkts == adv_pkts but maxLen still > adv_max_len, can't fix")
                    return
                index = self.create_max_packet_len()
                if index != -1:
                    print("split all: able to create max packet!")
                else:
                    print("tot_pkts == adv_pkts but can't reach max pkt len -- inject!")
                    self.injector.inject_one(self.flow.pkts[len(self.flow.pkts) - 1], self.adv_fwd_pkt_len_max)

        # else:
        #     print("cant converge to total_pkts == adv_pkts")


    def split_looper_start_with_max(self):
        i = totalLoops = pktsGreaterThanMaxPktLen = 0
        # SPLIT PACKETS, start with packets > maxPktLen set by user
        while self.flow.flowStats.flowLen < self.adv_tot_fwd_pkts:  # and self.flow.flowStats.maxLen > maxPktLen:
            if i == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS or pktsGreaterThanMaxPktLen == 0:
                    self.flow.calcPktLenStats()
                    # warnings.warn("Reached max pkt loops, can't split more pkts.  max pkt len too small")
                    return False
                i = 0
                totalLoops += 1
                pktsGreaterThanMaxPktLen = 0
                continue
            if self.flow.pkts[i].pload_len > self.adv_fwd_pkt_len_max:
                pktsGreaterThanMaxPktLen += 1
                if self.flow.pkts[i].pload_len // 2 < self.adv_fwd_pkt_len_min:  # don't split packet if goes below min pkt len
                    i += 1
                    continue
                self.splitPkt(self.flow.pkts[i], i)
                self.flow.calcPktLenStats()
                i += 2
            else:
                i += 1
        self.flow.calcPktLenStats()
        return True



    def split_looper_avoid_index(self, index_to_reserve):
        print("index to reserve: {}".format(index_to_reserve))
        i = totalLoops = 0
        while self.flow.flowStats.flowLen < self.adv_tot_fwd_pkts:
            if i == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    self.flow.calcPktLenStats()
                    return False
                i = 0
                totalLoops += 1
                continue
            if i == index_to_reserve:
                i += 1
            elif self.flow.pkts[i].pload_len > 1:  # could have option not to split if < adv_min_pkt_len
                if i < index_to_reserve:
                    index_to_reserve += 1
                self.splitPkt(self.flow.pkts[i], i)
                self.flow.calcPktLenStats()
                i += 2
            else:
                i += 1
        return True


    def split_looper_all(self, will_inject):        # sub_one just means will inject after split
        minPktFlag = False
        if self.adv_fwd_pkt_len_min > 0:
            minPktFlag = True
        pktsLessThanMinPktLen = 0
        i = totalLoops = 0
        if will_inject:
            inj = 1
        else:
            inj = 0
        while self.flow.flowStats.flowLen < self.adv_tot_fwd_pkts - inj:            # subtract one if know we're injecting at end
            if minPktFlag and self.flow.flowStats.flowLen <= pktsLessThanMinPktLen:
                print("Min Packet Length set by user too small!")
                print("Can't converge on avg. packet length.  Ignorning min pkt length requirement")
                minPktFlag = False
                totalLoops -= 1
            if i == self.flow.flowStats.flowLen:
                # print("sup")
                if totalLoops == MAX_PKT_LOOPS:
                    self.flow.calcPktLenStats()
                    print("Reached max pkt loops, can't split more pkts.  avg still > target avg.  NOT CONVERGED")
                    return False
                i = 0
                totalLoops += 1
                pktsLessThanMinPktLen = 0
                continue
            if minPktFlag and self.flow.pkts[i].pload_len // 2 < self.adv_fwd_pkt_len_min: #avoid splitting packets to get < min pkt len
                i += 1
                pktsLessThanMinPktLen += 1
            elif self.flow.pkts[i].pload_len > 0:
                self.splitPkt(self.flow.pkts[i], i)
                self.flow.calcPktLenStats()
                i += 2
            else:
                i += 1
        self.flow.calcPktLenStats()
        return True
            # print("flow len: {}".format(self.flow.flowStats.flowLen))


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
        biPkt = self.flow.biPkts[len(self.flow.biPkts) - 1]
        for biPktObj in reversed(self.flow.biPkts):
            if biPktObj.ts < pkt.ts and biPktObj.http_pload:
                flag = True
                biPkt = biPktObj
                break
        if flag:
            return biPkt
        else:
            return flag

    def distribute_payload(self, pkt_1, pkt_2):
        # sum of these two pkts have pload_len > max pkt len
        total_len = pkt_1.pload_len + pkt_2.pload_len
        p2_new_len = total_len - self.adv_fwd_pkt_len_max
        p1_extra_len = int(pkt_2.pload_len - p2_new_len)
        pload_for_p1 = pkt_2.http_pload[:p1_extra_len]

        pkt_1.http_pload += pload_for_p1
        pkt_1.ip_len += p1_extra_len

        pkt_2.http_pload = pkt_2.http_pload[p1_extra_len:]
        pkt_2.ip_len -= p1_extra_len

    def create_max_packet_len(self):
        index = -1
        cur = self.flow.pkts[0]
        for i in range(1, len(self.flow.pkts)):
            if i + 1 == len(self.flow.pkts):
                return index
            print("len pkts: {}, {}".format(cur.pload_len, self.flow.pkts[i].pload_len))
            if cur.pload_len + self.flow.pkts[i].pload_len >= self.adv_fwd_pkt_len_max:
                print("merge pkts to set max pkt len")  # not really merge just push data to second packet
                self.distribute_payload(cur, self.flow.pkts[i])
                index = i - 1
                return index
            cur = self.flow.pkts[i]

    def split_max_packet(self):
        # can't avoid index. split max pkt
        print("can't keep max pkt len, must split")
        totalLoops = 0
        splits = 1
        base_index = self.flow.flowStats.maxLenIndex
        while self.flow.flowStats.flowLen < self.adv_tot_fwd_pkts:
            if totalLoops > MAX_SPLIT_PKT:
                return False
            i = base_index
            # print(i)
            for k in range(splits):
                # print(i, splits)
                # print(self.flow.pkts[i].ts)
                if self.flow.pkts[i].pload_len > 1:
                    self.splitPkt(self.flow.pkts[i], i)
                    self.flow.calcPktLenStats()
                    if self.flow.flowStats.flowLen == self.adv_tot_fwd_pkts - 1:    # -1 because we will inject pkt after
                        return True
                    # splits *= 2
                    i += 2
                else:
                    i += 1
            splits *= 2
            # print("--------")
            totalLoops += 1
        return True

    def set_min_packet_length(self):
        print("fixing min packet length")

        if self.flow.flowStats.minLen < self.adv_fwd_pkt_len_min:
            print("need to increase min pkt len")
            print("can't do this. incr. # pkts and incr. min pkt len")
        else:
            print("need to decrease min pkt len")
            self.injector.inject_one(self.flow.pkts[len(self.flow.pkts) - 1], self.adv_fwd_pkt_len_min)