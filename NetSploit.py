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

        self.mergeModifiedPkts()

    def mergeModifiedPkts(self):
        for tuple,flow in self.flowTable.FT.items():
            for pkt in flow.pkts:
                # if pkt.ip_src == "172.217.2.4" and pkt.ip_dst == "10.201.73.154" and pkt.src_port == 443 and pkt.dst_port == 60043:
                #     print(pkt)
                self.pktMerger.mergePkt(pkt)



        # Delete Flow from FlowTable
        #self.flowTable.delFlow(pkt_5_tuple)
