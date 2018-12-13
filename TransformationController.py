from TransPkt import TransPkt


class TransformationController:
    def __init__(self, pktList):
        self.pktList = pktList

    def Process(self):
        raise NotImplementedError()

class TransPktLens(TransformationController):
    def __init__(self, pktList):
        TransformationController.__init__(self, pktList)
        print("Creating new TransPktLens Object")

    def Process(self):
        print("Transforming Pkt Lengths on these pkts: {}".format(self.pktList))

class TransIATimes(TransformationController):
    def __init__(self, pktList):
        TransformationController.__init__(self, pktList)
        print("Creating new TransIATimes Object")

    def Process(self):
        print("Transforming IA Times on these pkts: {}".format(self.pktList))