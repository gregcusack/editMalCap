import copy
from FlowTable import FlowTable

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
        print(self.config)
        print(self.flow.flowStats)
        #self.testPktSplit()

        #self.mergePkt(self.flow.pkts[9], self.flow.pkts[10])
        #print(self.flow.pkts[10])
        #self.splitPkt(self.flow.pkts[10])
        #self.flow.pkts.sort()
        #self.flow.calcPktLenStats()

        # Need some sort of iteration
        if self.flow.flowStats.avgLen < self.config["pktLens"]["avg"]:
            i = 0
            while self.flow.flowStats.avgLen < self.config["pktLens"]["avg"]:
                if i+1 == self.flow.flowStats.flowLen:
                    print("Reached end of pkt list, can't merge more pkts.  avg still < target avg")
                    print("i: {}".format(i))
                    break
                if self.flow.pkts[i].frame_len + self.flow.pkts[i+1].frame_len >= 3000:
                    i += 1
                else:
                    if self.mergePkt(self.flow.pkts[i], self.flow.pkts[i+1]):
                        self.flow.calcPktLenStats()
                    else:
                        i += 1
                    # TODO: figure out how to iterate over packets when you remove one in the list
                    # two iterators, adjust accordingly based on how lists change when iterating through them
                    # Everything shifts down one when an element is removed
                    # packet was removed
                # else:
                #     i += 1

                # self.flow.calcPktLenStats()
                #i += 1
        elif self.flow.flowStats.avgLen > self.config["pktLens"]["avg"]:
            i = 0
            while self.flow.flowStats.avgLen > self.config["pktLens"]["avg"]:
                if i == self.flow.flowStats.flowLen:
                    print("Reached end of pkt list, can't split more pkts.  avg still > target avg")
                    print("i: {}".format(i))
                    break
                self.splitPkt(self.flow.pkts[i], i)
                self.flow.calcPktLenStats()
                i += 2


        #while self.config.
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

        #self.flow.calcPktLenStats()
        #self.flow.get
        print(self.flow.flowStats)
        #print(self.flow.biPkts)

    def mergePkt(self, pkt, npkt):
        #print("Merging Pkts") # probably shouldn't/can't merge pkts without a payload???

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

    #     # Probably create new pkt from 1
    #     self.deletePkt()
    #
    # def deletePkt(self):
    #     print("Deleting Pkt")

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
        dupPkt.ip_id += 1  # increment ipID (this will need to be adjusted at end of flow processing)
        self.flow.pkts.insert(index, dupPkt)
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
        self.flow.calcPktIAStats()
        #TODO: make sure lenStats are updated before this section!
        print("Transforming IA Times on these pkts: {}".format(self.flow))