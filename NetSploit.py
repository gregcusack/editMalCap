from FlowTable import FlowTable, FlowFilter
from PktMerger import PktMerger
from TransformClasses.TransformationController import TransformationController as TC

class NetSploit:
    def __init__(self, config):             # this should be a map of our config file
        # try to keep this just objects
        self.filter = FlowFilter(config.flows)
        self.flowTable = FlowTable()
        self.pktMerger = PktMerger(config.merge_batch_size)
        self.config = config

    def loadFlowTable(self, pkt):
        addToFT = self.filter.needsTrans(pkt.flow_tuple)
        if addToFT:
            #print("Send packet for transformation")
            self.flowTable.procPkt(pkt, addToFT)
        else:
            #print("No Transformation needed.  Sending to Pkt Merger")
            self.pktMerger.mergePkt(pkt)

    def ProcessFlows(self):
       for tuple,flow in self.flowTable.FT.items():
           if flow.procFlag:
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
