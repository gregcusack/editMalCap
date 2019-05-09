from FlowTable import FlowTable, FlowFilter
from PktMerger import PktMerger
from TransformClasses.TransformationController import TransformationController as TC
from TestClasses.TestFlowTransformation import TestFlowTransformation
import logging, time

class NetSploit:
    def __init__(self, config, attack):             # this should be a map of our config file
        # try to keep this just objects
        # print(config.flows)
        self.filter = FlowFilter(config.flows)
        self.flowTable = FlowTable()
        self.pktMerger = PktMerger()
        self.config = config
        ts = time.time()
        self.total_flows_to_modify = config.total_flows_to_modify
        self.flows_processed = 0

        logger_name = "Logs/" + attack + "/" + attack + "-logger-info-" + str(ts) + ".log"
        # logger_name = "logger-debug.log"
        logging.basicConfig(filename=logger_name,
                            format='%(message)s',
                            filemode='w')
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)
        print("Logging to: {}".format(logger_name))

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
        len_FT = len(self.flowTable.FT)
        # print("total flows in table: {}".format(len_FT))
        self.logger.info("total flows in table: {}".format(len_FT))
        count = 0
        for tuple,flow in self.flowTable.FT.items():
            # print("flow start, end ts, end fin?: {}, {}, {}".format(flow.flowStartTime, flow.flowEndTime, flow.end_fin))
            # print("processing: {} -- {}".format(tuple, flow))
            biflow = False # need to check if biflow exists
            if flow.flowKey[0] == 6:
                biflowkey = flow.biFlowKey
            else:
                biflowkey = flow.biFlowKey[:-1]      # UDP

            if (biflowkey, tuple[1]) in self.flowTable.FT:
                biFK = (biflowkey, tuple[1])
                flow.biPkts = self.flowTable.FT[biFK].pkts  # give flow access to opposite dir flow
                flow.biFlowKey = biFK
                # print("flow bP: {}".format(flow.biPkts))
                # print("BIFLOW!")
                biflow = True
            # else:
            #     print("NO BIFLOW!")

            # for pkt in flow.pkts:
            #     print(pkt.get_flags(), pkt.ts)

            flow.flowStats.get_flag_counts(flow.pkts)
            if flow.procFlag:
                print("Processing flow {}/{}".format(count,len_FT))
                self.logger.info("Processing flow {}/{}".format(count, len_FT))
                # print(len(flow.pkts), len(flow.biPkts))
                self.transformFlow(flow, biflow)
            count += 1

        self.extend_flows()
        self.check_pkts()
            # print("ProcProcProcProc")

    def transformFlow(self, flow, biflow):
        flow.calcPktIAStats()
        flow_key = flow.flowKey
        flag = False
        for f in self.config.flows:
            if flow_key == f[0]:
                if flow.flowKey[0] == 6:
                    config = self.config.flows
                    flag = True
                    break
        if not flag:
            return

        config = self.needsTransform(flow, config)
        if not config:
            # print("No trans for flow: {}".format(flow))
            # print("\n#####################")
            return

        # print("config returning: {}".format(config))

        tf = TC(config, flow, biflow, self.logger, self.flowTable.FT) #(config.5_tuple, Flow)


        tf.buildTransformations()
        tf.runTransformations()
        self.flows_processed += 1
        print("Number of flows processed: {}/{}".format(self.flows_processed, self.total_flows_to_modify))
        self.logger.info("Number of flows processed: {}/{}".format(self.flows_processed, self.total_flows_to_modify))
        print("Amount flow extended: {} (s)".format(flow.amount_flow_extended))

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
        # print(splitFlows)
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

    # Match flow config to pcap to flow in flow table (need due to timeouts)
    def needsTransform(self, flow, config):
        flow.calcPktLenStats()
        flow.calcPktIAStats()
        # print("config in needsTransform(): {}".format(config))
        # fc = config["features"]
        flowDur = round(flow.flowStats.flowDuration * 1000000)

        configToReturn = None
        for k,v in config.items():
            if v["features"]["Flow Duration"]["og"] == flowDur:
                fc = v["features"]
                configToReturn = v
                # print("config found: {}".format(configToReturn))
                # print("!!!!!!!!!!!!!!!")
        if configToReturn == None:
            # print("flow dur not matched: {}".format(flowDur))
            return False

        print("dur: (ogFlow, actFlow): ({}, {})".format(fc["Flow Duration"]["og"], flowDur))
        print("pkts: (og, actual): ({}, {})".format(fc["Tot Fwd Pkts"]["og"], flow.flowStats.flowLen))
        self.logger.info("dur: (ogFlow, actFlow): ({}, {})".format(fc["Flow Duration"]["og"], flowDur))
        self.logger.info("pkts: (og, actual): ({}, {})".format(fc["Tot Fwd Pkts"]["og"], flow.flowStats.flowLen))

        match_counter_checker = 0
        assert_flag = False

        if flowDur != fc["Flow Duration"]["og"]:
            match_counter_checker += 1
            assert_flag = True
            return False
        if flow.flowStats.flowLen != fc["Tot Fwd Pkts"]["og"]:
            match_counter_checker += 1
            assert_flag = True
            return False
        if flow.biPkts:
            if len(flow.biPkts) != fc["Tot Bwd Pkts"]["og"]:
                match_counter_checker += 1
                assert_flag = True
                return False
        if flow.flowStats.flowLenBytes != fc["TotLen Fwd Pkts"]["og"]:
            match_counter_checker += 1
            assert_flag = True
            return False

        return configToReturn


    def extend_flows(self):
        d = {} # holds flow/tuple in order
        for tuple, flow in self.flowTable.FT.items():
            fk = tuple[0]
            if fk not in d:
                d[fk] = []
            d[fk].append((tuple, flow))
        for tuple, flows in d.items():
            flows.sort()
            # print(flows[0])
            i = 0
            # prev_flow = flows[i][1]
            # print(len(flows))
            # print("flows: {}".format(flows))
            # print("init len flows: {}".format(len(flows)))
            for i in range(0, len(flows) - 1):
                flow = flows[i][1]
                next_flow = flows[i + 1][1]
                # flow.calcPktLenStats()
                # next_flow.calcPktLenStats()
                # print("flow: {}".format(flow))
                timeout = flows[i][0][0]
                if flow.flowEndTime > next_flow.flowStartTime:
                    # print("flow exceed: {}".format(flow))
                    # print("WOAH: {}".format(flow))
                    # print("flow extend: {}".format(flow.amount_flow_extended))
                    toextend = flow.amount_flow_extended
                    # print("len flows: {}".format(len(flows)))
                    # print("i: {}".format(i))
                    for j in range(i + 1, len(flows)):
                        flow_to_mod = flows[j][1]
                        # print("flow to mod: {}".format(flow_to_mod))
                        for pkt in flow_to_mod.pkts:
                            # print(pkt.ts)
                            pkt.ts += toextend
                            # print("pkt.ts: {}".format(pkt.ts))
                            # print(pkt.get_flags())
                        if flow_to_mod.biPkts:
                            for pkt in flow_to_mod.biPkts:
                                pkt.ts += toextend
                                # print("bipkt.ts: {}".format(pkt.ts))
                                # print(pkt.get_flags())
                prev_flow = flow
                i += 1

        # print(d)


    def check_pkts(self):
        print("Running check pkts")
        for tuple, flow in self.flowTable.FT.items():
            for pkt in flow:

                if pkt.frame_len > 65535:
                    pkt.frame_len = 65535

                if pkt.ip_len > 65535:
                    pkt.ip_len = 65535

                if pkt.ip_id > 65535:
                    pkt.ip_id = 65535

                if pkt.src_port > 65535:
                    pkt.src_port = 65535
                if pkt.dst_port > 65535:
                    pkt.dst_port = 65535
                if pkt.tcp_window > 65535:
                    pkt.tcp_window = 65535
                # @property
                # def tcp_window(self):
                #     return self.pkt[TCP].window


    def run_flow_transformation_test(self):
        TestFT = TestFlowTransformation(self.config, self.flowTable)
        TestFT.check_flow_transformations()

    def print_feats_to_match(self, fc, flow):
        print("flow: {}".format(flow))
        print("flowdDur (is, should be): ({}, {})".format(flow.flowStats.flowDuration * 1000000, fc["Flow Duration"]["og"]))
        print("flowlen (is, should be): ({}, {})".format(flow.flowStats.flowLen, fc["Tot Fwd Pkts"]["og"]))
        if flow.biPkts:
            print("flow bi pkts: (is, should be): ({}, {})".format(len(flow.biPkts), fc["Tot Bwd Pkts"]["og"]))
        print("flowlenbytes (is, should be): ({}, {})".format(flow.flowStats.flowLenBytes, fc["TotLen Fwd Pkts"]["og"]))