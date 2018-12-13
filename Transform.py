#from TransPktLens import TransPktLens
#from TransIATimes import TransIATimes


class Transform:
    def __init__(self, pktList, config):
        self.pktList = pktList
        self.config = config

    def Process(self):
        raise NotImplementedError()


class TransPktLens(Transform):
    def __init__(self, pktList, config):
        Transform.__init__(self, pktList, config)
        print("Creating new TransPktLens Object")

    def Process(self):
        print("Transforming Pkt Lengths on these pkts: {}".format(self.pktList))

        # self.pktList[0].eth_src = "11:11:11:11:11:11"
        # self.pktList[0].eth_dst = "22:22:22:22:22:22"


class TransIATimes(Transform):
    def __init__(self, pktList, config):
        Transform.__init__(self, pktList, config)
        print("Creating new TransIATimes Object")

    def Process(self):
        print("Transforming IA Times on these pkts: {}".format(self.pktList))

        # print("pktList[0] eth_src: {}".format(self.pktList[0].eth_src))
        # print("pktList[0] eth_dst: {}".format(self.pktList[0].eth_dst))