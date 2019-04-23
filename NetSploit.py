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
        # print(pkt.biflow_tuple)
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
            # print("processing: {} -- {}".format(tuple, flow))
            biflow = False # need to check if biflow exists
            if flow.flowKey[0] == 6:
                biflowkey = flow.biFlowKey
            else:
                biflowkey = flow.biFlowKey[:-1]      # UDP

            if (biflowkey, tuple[1]) in self.flowTable.FT:
                biFK = (biflowkey, tuple[1])
                flow.biPkts = self.flowTable.FT[biFK].pkts  # give flow access to opposite dir flow
                # print("flow bP: {}".format(flow.biPkts))
                # print("BIFLOW!")
                biflow = True
            else:
                print("NO BIFLOW!")

            if flow.procFlag:
                self.transformFlow(flow, biflow)

            # print("ProcProcProcProc")

    def transformFlow(self, flow, biflow):
        if flow.flowKey[0] == 6:
            config = self.config.flows[flow.flowKey]
        else:
            config = self.config.flows[flow.flowKey[:-1]]

        if not self.needsTransform(flow, config):
            print("No trans for flow: {}".format(flow))
            print("\n#####################")
            return

        tf = TC(config, flow, biflow) #(config.5_tuple, Flow)


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
        # print("redistributing flow table")
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

    def needsTransform(self, flow, config):
        flow.calcPktLenStats()
        flow.calcPktIAStats()

        fc = config["features"]

        match_counter_checker = 0
        assert_flag = False
        flowDur = round(flow.flowStats.flowDuration * 1000000)
        if flowDur != fc["Flow Duration"]["og"]:
            match_counter_checker += 1
            assert_flag = True
        if flow.flowStats.flowLen != fc["Tot Fwd Pkts"]["og"]:
            match_counter_checker += 1
            assert_flag = True
        if flow.biPkts:
            if len(flow.biPkts) != fc["Tot Bwd Pkts"]["og"]:
                match_counter_checker += 1
                assert_flag = True
        if flow.flowStats.flowLenBytes != fc["TotLen Fwd Pkts"]["og"]:
            match_counter_checker += 1
            assert_flag = True

        if assert_flag:
            if flow.biPkts and match_counter_checker != 4:
                print("ERROR! Match count checker != 4.  EXITING...")
                self.print_feats_to_match(fc, flow)
                exit(-1)
            elif not flow.biPkts and match_counter_checker != 3:
                print("ERROR! Match count checker != 3.  EXITING...")
                self.print_feats_to_match(fc, flow)
                exit(-1)
            return False
        return True

    def print_feats_to_match(self, fc, flow):
        flowDur = round(flow.flowStats.flowDuration * 1000000)
        print("Flow id: {}".format(flow))
        print("flow_dur: {}, {}".format(flowDur, fc["Flow Duration"]["og"]))
        print("flow_len: {}, {}".format(flow.flowStats.flowLen, fc["Tot Fwd Pkts"]["og"]))
        print("biflow_len: {}, {}".format(len(flow.biPkts), fc["Tot Bwd Pkts"]["og"]))
        print("flow_len_bytes: {}, {}".format(flow.flowStats.flowLenBytes, fc["TotLen Fwd Pkts"]["og"]))
        total_len = 0
        for pkt in flow.pkts:
            print(pkt.pload_len)
            total_len += pkt.pload_len
        print("flow len bytes: {}".format(total_len))
