import copy
from FlowTable import FlowTable

class Transform:
    def __init__(self, flowObj, config):
        self.flow = flowObj
        self.config = config

    def Process(self):
        raise NotImplementedError()


class TransPktLens(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        print("Creating new TransPktLens Object")

    def Process(self):
        self.flow.calcPktLenStats()
        #print(self.flow.flowStats)
        #self.testPktSplit()

        self.mergePkt(self.flow.pkts[9], self.flow.pkts[10])


        self.flow.calcPktLenStats()
        #print(self.flow.biPkts)

    def mergePkt(self, pkt, npkt):
        print("Merging Pkts") # probably shouldn't/can't merge pkts without a payload???

        if pkt.http_pload and npkt.http_pload:# and (pkt.tcp_flags == npkt.tcp_flags): # make sure both pkts have payload and same flags
            print("prePKT: {}".format(pkt))
            print("preNPKT: {}".format(npkt))

            pkt.http_pload += npkt.http_pload
            pkt.ip_len = pkt.ip_len + len(npkt.http_pload)

            print("postPKT: {}".format(pkt))
            print("postNPKT: {}".format(npkt))

            self.flow.pkts.remove(npkt)
        else:
            print("CAN'T MERGE PACKETS")


        # pkt.pload += npkt.pload
        # increase ip.len of pkt
        # think we can leave the seq # and ack num alone for these
        # keep ts of pkt
        # delete npkt


        # Probably create new pkt from 1
        self.deletePkt()

    def deletePkt(self):
        print("Deleting Pkt")

    def splitPkt(self, pkt):
        dupPkt = copy.deepcopy(pkt)

        if pkt.http_pload:
            self.splitPayload(pkt, dupPkt)
        else:
            self.fixACKnum(pkt, dupPkt)

        # update IP ID
        dupPkt.ip_id += 1  # increment ipID (this will need to be adjusted at end of flow processing)
        return dupPkt

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

class TransIATimes(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        print("Creating new TransIATimes Object")

    def Process(self):
        self.flow.calcPktIAStats()
        #TODO: make sure lenStats are updated before this section!
        print("Transforming IA Times on these pkts: {}".format(self.flow))