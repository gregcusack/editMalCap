from FlowTable import FlowTable, FlowFilter
from PktMerger import PktMerger
from TransformClasses.TransformationController import TransformationController as TC

class NetSploit:
    def __init__(self, config):             # this should be a map of our config file
        # try to keep this just objects
        self.flowTable = FlowTable()
        self.filter = FlowFilter(config.flows)
        self.pktMerger = PktMerger(config.merge_batch_size)
        self.config = config

    def loadFlowTable(self, pkt):
        if self.filter.needsTrans(pkt.flow_tuple):
            #print("Send packet for transformation")
            self.flowTable.procPkt(pkt)
        else:
            #print("No Transformation needed.  Sending to Pkt Merger")
            self.pktMerger.mergePkt(pkt)

    def ProcessFlows(self):
       for tuple,flow in self.flowTable.FT.items():
           flow.biPkts = self.flowTable.FT[flow.biFlowKey].pkts      # give flow access to opposite dir flow
           self.transformFlow(flow)

    def transformFlow(self, flow):

        tf = TC(self.config.flows[flow.flowKey], flow) #(config.5_tuple, Flow)
        tf.buildTransformations()
        tf.runTransformations()
        #TODO: Transform Flow!  Call: TransPktLens.py
        #TODO: Transform Flow!  Call: TransIATimes.py
        #TODO: Fix Timestamps!  Call: FixTimestamps.py

        # Delete Flow from FlowTable
        #self.flowTable.delFlow(pkt_5_tuple)
