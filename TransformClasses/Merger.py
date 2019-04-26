

class Merger:
    def __init__(self, flowObj, config):
        self.flow = flowObj
        self.config = config

        self.og_tot_fwd_pkts = self.config["Tot Fwd Pkts"]["og"]
        self.adv_tot_fwd_pkts = self.config["Tot Fwd Pkts"]["adv"]

        self.og_fwd_pkt_len_max = self.config["Fwd Pkt Len Max"]["og"]
        self.adv_fwd_pkt_len_max = self.config["Fwd Pkt Len Max"]["adv"]
        self.og_fwd_pkt_len_min = self.config["Fwd Pkt Len Min"]["og"]
        self.adv_fwd_pkt_len_min = self.config["Fwd Pkt Len Min"]["adv"]

    def mergeLooper(self):
        print("merge looper (og, adv): ({}, {})".format(self.og_tot_fwd_pkts, self.adv_tot_fwd_pkts))
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

