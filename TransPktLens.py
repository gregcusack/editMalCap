from TransPkt import TransPkt

"""
Need Config input
    1) # of pkts
    2) pkt lens
"""

class TransPktLens:
    def __init__(self):
        print("Creating new TransPktLens Object")

    def Process(self, pktList):
        print("Transforming Pkt Lengths on these pkts: {}".format(pktList))