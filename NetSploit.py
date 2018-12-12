from FlowTable import FlowTable, FlowFilter
from TransPkt import TransPkt
from PktMerger import PktMerger

class NetSploit:
    def __init__(self, config):             # this should be a map of our config file
        # try to keep this just objects
        self.flowTable = FlowTable()
        self.filter = FlowFilter(config.flow_filter_config)
        self.pktMerger = PktMerger(config.merge_batch_size)


    def Process(self, pkt):
        if self.filter.needsTrans(pkt):
            print("Send packet for transformation")
            self.flowTable.addFlow(pkt)
        else:
            print("No Transformation needed.  Sending to Pkt Merger")
            self.pktMerger.mergePkt(pkt)
            # need to send to Pkt Merger here


