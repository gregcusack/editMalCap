from PktMerger import PktMerger


class TestNetSploit:
    def __init__(self, netSploit=None, flowTable=None, config=None, filter=None, merger=None):
        if netSploit:
            print("Test NetSploit")
        if flowTable:
            print("test Flow Table")
        if config:
            print("Test Config")
        if filter:
            print("Test Filter")
        if merger:
            TestPktMerger(merger)



class TestPktMerger:
    def __init__(self, MergerClass):
        self.checkSort(MergerClass.inQueue)

    def checkSort(self, queue):
        assert all(queue[i] <= queue[i + 1] for i in range(len(queue) - 1))