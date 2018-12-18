from TransformClasses.Transform import Transform
"""
Need Config input
    1) # of pkts
    2) pkt lens
"""

class TransPktLens(Transform):
    def __init__(self, pktList, config):
        Transform.__init__(self, pktList, config)
        print("Creating new TransPktLens Object")

        # self.pktList[0].eth_src = "11:11:11:11:11:11"
        # self.pktList[0].eth_dst = "22:22:22:22:22:22"

    def Process(self, pktList):
        print("Transforming Pkt Lengths on these pkts: {}".format(self.pktList))

    def getMinLen(self):
        return min(int(k) for k in self.pktList)
        print("Min Len")

    def getMaxLen(self):
        print("Max Len")

    def getAvgLen(self):
        print("avg len")

    def getStdLen(self):
        print("std len")