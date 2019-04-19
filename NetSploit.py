from FlowTable import FlowTable, FlowFilter
from PktMerger import PktMerger
from TransformClasses.TransformationController import TransformationController as TC

class NetSploit:
    def __init__(self, config):             # this should be a map of our config file
        # try to keep this just objects
        self.filter = FlowFilter(config.flows)
        self.flowTable = FlowTable()
        self.pktMerger = PktMerger()
        self.config = config

    def loadFlowTable(self, pkt):
        # print(pkt.flow_tuple)
        addToFT = self.filter.needsTrans(pkt.flow_tuple)
        if addToFT:
            # print("Send packet for transformation")
            self.flowTable.procPkt(pkt, addToFT)
        else:
            # print("pkt no trans just merge: {}".format(pkt))
            self.pktMerger.mergePkt(pkt)

    def ProcessFlows(self):
        # print("flow table: {}".format(self.flowTable.FT))
        for tuple,flow in self.flowTable.FT.items():
           print("processing: {} -- {}".format(tuple, flow))
           biflow = False # need to check if biflow exists
           if flow.procFlag:
               if flow.flowKey[0] == 6:
                   biflowkey = flow.biFlowKey
               else:
                   biflowkey = flow.biFlowKey[:-1]      # UDP

               if (biflowkey, tuple[1]) in self.flowTable.FT:
                   biFK = (biflowkey, tuple[1])
                   flow.biPkts = self.flowTable.FT[biFK].pkts  # give flow access to opposite dir flow
                   print("flow bP: {}".format(flow.biPkts))
                   biflow = True
               else:
                   print("NO BIFLOW!")

               self.transformFlow(flow, biflow)

    def transformFlow(self, flow, biflow):
        if flow.flowKey[0] == 6:
            config = self.config.flows[flow.flowKey]
        else:
            config = self.config.flows[flow.flowKey[:-1]]
        tf = TC(config, flow, biflow) #(config.5_tuple, Flow)
        print(config)
        tf.buildTransformations()
        tf.runTransformations()
        # self.mergeModifiedPkts()

    def mergeModifiedPkts(self):
        for tuple,flow in self.flowTable.FT.items():
            # print("flow to store: {}".format(flow))
            for pkt in flow.pkts:
                #print(pkt)
                # if pkt.flow_tuple == (6, '192.168.10.14', 49474, '104.97.95.20', 443):
                #     print("to merge: {}".format(pkt))
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

    def printFlowTable(self):
        print("flowtable: {}".format(self.flowTable.FT))

        # Delete Flow from FlowTable
        #self.flowTable.delFlow(pkt_5_tuple)
