import bisect

class PktMerger:
    def __init__(self, batch_size):
        self.inQueue = []
        self.BatchSize = batch_size

    def mergePkt(self, pkt):
        bisect.bisect(self.inQueue, pkt)
        bisect.insort(self.inQueue, pkt)