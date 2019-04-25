import copy

MAX_PKT_LOOPS = 6
MAX_SPLIT_PKT = 6 #10 should work but just takes longer
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
        # print("transform create")
        #self.pktsToRemove = []

    def split_max_lens_eq(self):
        print("split_max_lens_eq (og, adv): ({}, {})".format(self.og_tot_fwd_pkts, self.adv_tot_fwd_pkts))
        if self.flow.flowStats.maxLen == 0:
            print("max pkt length == 0.  Can't split.  Returning")
            return
        i = totalLoops = 0
        while self.flow.flowStats.flowLen < self.adv_tot_fwd_pkts:
            if i == self.flow.flowStats.flowLen:
                if totalLoops == MAX_PKT_LOOPS:
                    self.flow.calcPktLenStats()
                    break
                i = 0
                totalLoops += 1
                continue
            if i == self.flow.flowStats.maxLenIndex:
                i += 1
            elif self.flow.pkts[i].pload_len > 1:  # could have option not to split if < adv_min_pkt_len
                self.splitPkt(self.flow.pkts[i], i)
                self.flow.calcPktLenStats()
                i += 2
            else:
                i += 1

        totalLoops = 0
        splits = 1
        base_index = self.flow.flowStats.maxLenIndex
        while self.flow.flowStats.flowLen < self.adv_tot_fwd_pkts:
            if totalLoops > MAX_SPLIT_PKT:
                break
            i = base_index
            # print(i)
            for k in range(splits):
                # print(i, splits)
                # print(self.flow.pkts[i].ts)
                if self.flow.pkts[i].pload_len > 1:
                    self.splitPkt(self.flow.pkts[i], i)
                    self.flow.calcPktLenStats()
                    if self.flow.flowStats.flowLen == self.adv_tot_fwd_pkts:
                        break
                    # splits *= 2
                    i += 2
                else:
                    i += 1
            splits *= 2
            # print("--------")
            totalLoops += 1

        if totalLoops > MAX_SPLIT_PKT:
            print("CAN'T CONVERGE!")
        if self.flow.flowStats.maxLen < self.adv_fwd_pkt_len_max:
            print("inject packet!")

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