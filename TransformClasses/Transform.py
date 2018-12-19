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
        self.splitPkt(self.flow.pkts[0])
        print("Transforming Pkt Lengths on these pkts: {}".format(self.flow))
        print(self.flow.biPkts)

    def mergePkt(self):
        print("Merging Pkts")
        # Probably create new pkt from 1
        self.deletePkt()

    def deletePkt(self):
        print("Deleting Pkt")

    def splitPkt(self, pkt):
        print("Splitting Pkt")
        dupPkt = copy.deepcopy(pkt) #pkt.copy() #self.duplicatePkt()
        # if pkt[TCP].len
        if pkt.http_pload:
            len_payload = len(pkt.http_pload)
            ip_hdr_len = pkt.ip_len - len_payload
            dupPkt.http_pload = pkt.http_pload[len_payload//2:]
            pkt.http_pload = pkt.http_pload[:len_payload//2]

            print("Change IP len")
            pkt.ip_len = ip_hdr_len + len(pkt.http_pload)
            dupPkt.ip_len = ip_hdr_len + len(pkt.http_pload)

            print("split seq num")
            dupPkt.seq_num += len(pkt.http_pload)

        else:
            print("split ack num")
            # pkt ack_num stays same
            # need length of last Rx packet with len > 66 in other direction

            # Gets most recent biPkt.  need length
            #TODO: you need to loop through biPkt list from end to start (aka most recent to most distant)
            biPkt = self.getMostRecentBiPkt(dupPkt)
            if biPkt:
                print(dupPkt)
                print(biPkt)
                if not biPkt.http_pload:
                    print("ERROR: ACKing an ACK.  uh oh!  biPkt should have a payload!")
                    exit(-1)
                dupPkt.ack_num += len(biPkt.http_pload)




            #dupPkt.

        # change IP ID
        dupPkt.ip_id += 1  # increment ipID (this will need to be adjusted at end of flow processing)

        print(pkt)
        print(dupPkt)

        return dupPkt


    def duplicatePkt(self, pkt):
        print("Duplicating Pkt")
        return pkt.copy()

    # TODO (high): need to loop from most recent pkt to most distant pkt
    # That way we find the closes biPkt to dupPkt that has payload w/o storing a bunch of pkts
    # TODO (low): optimize to do O(log n) search since biPkt list is sorted
    def getMostRecentBiPkt(self, pkt):
        flag = False
        biPkt = self.flow.biPkts[0]
        for biPktObj in self.flow.biPkts:  # start at 1st element in list not 0th
            if biPktObj.ts < pkt.ts:
                flag = True
                biPkt = biPktObj
            else:
                break
        if flag:
            return biPkt
        else:
            return flag



class TransIATimes(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        print("Creating new TransIATimes Object")

    def Process(self):
        self.flow.calcPktIAStats()
        #TODO: make sure lenStats are updated before this section!
        print("Transforming IA Times on these pkts: {}".format(self.flow))