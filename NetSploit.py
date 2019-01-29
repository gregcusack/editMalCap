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
               #self.flowTable.FT[flow.flowKey].getDiffs()
               self.transformFlow(flow)

    def transformFlow(self, flow):

        tf = TC(self.config.flows[flow.flowKey], flow) #(config.5_tuple, Flow)
        print(self.config.flows[flow.flowKey])
        tf.buildTransformations()
        tf.runTransformations()
        # TODO: decide if this needs to be implemented...
        # if tf.splitFlowFlag:
        #     self.redistributeFlowTable(flow)
        #TODO: Transform Flow!  Call: TransPktLens.py
        #TODO: Transform Flow!  Call: TransIATimes.py
        #TODO: Fix Timestamps!  Call: FixTimestamps.py

        self.mergeModifiedPkts()

    def mergeModifiedPkts(self):
        for tuple,flow in self.flowTable.FT.items():
            print(flow)
            for pkt in flow.pkts:
                #print(pkt)
                # if pkt.ip_src == "172.217.2.4" and pkt.ip_dst == "10.201.73.154" and pkt.src_port == 443 and pkt.dst_port == 60043:
                #     print(pkt)
                self.pktMerger.mergePkt(pkt)

    def redistributeFlowTable(self, flow):
        print("redistributing flow table")
        splitFlows = self.flowTable.FT[flow.flowKey].pkts
        print(splitFlows)
        del self.flowTable.FT[flow.flowKey]
        for pkt in splitFlows:
            if pkt.flow_tuple not in self.flowTable.FT:
                self.flowTable.FT[pkt] = []
            self.flowTable.FT[pkt.flow_tuple] = pkt
        print(self.flowTable.FT)



        # Delete Flow from FlowTable
        #self.flowTable.delFlow(pkt_5_tuple)
