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
        print("Transforming Pkt Lengths on these pkts: {}".format(self.flow))

    def mergePkt(self):
        print("Merging Pkts")
        # Probably create new pkt from 1
        self.deletePkt()

    def deletePkt(self):
        print("Deleting Pkt")

    def splitPkt(self):
        self.duplicatePkt()
        print("Splitting Pkt")

    def duplicatePkt(self):
        print("Duplicating Pkt")


class TransIATimes(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        print("Creating new TransIATimes Object")

    def Process(self):
        self.flow.calcPktIAStats()
        #TODO: make sure lenStats are updated before this section!
        print("Transforming IA Times on these pkts: {}".format(self.flow))