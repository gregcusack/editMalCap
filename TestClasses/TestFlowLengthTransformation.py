from scapy.all import *
from TransformClasses.TransPkt import TransPkt
import logging


class TestFlowLengthTransformation:
    def __init__(self, config, flow_table):
        self.config = config
        self.flow_table = flow_table
        logging.basicConfig(filename="logger.log",
                            format='%(message)s',
                            filemode='w')
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)

    def check_length_transformations(self):

        for tuple, flow in self.flow_table.FT.items():
            flag = False
            flow.calcPktLenStats()
            try:
                fc = self.config.flows[flow.flowKey]["features"]
                flag = True
            except KeyError:
                pass

            if flag and self.match_flow(flow, fc):
                self.logger.info("Testing Flow: {}".format(flow))
                # print("(flow len, adv flow len): ({}, {})".format(flow.flowStats.flowLen, fc["Tot Fwd Pkts"]["adv"]))
                if flow.flowStats.flowLen != int(fc["Tot Fwd Pkts"]["adv"]):
                    self.logger.warning("Total Packets differ (is, should be): ({}, {})".format(flow.flowStats.flowLen,
                                                                                                fc["Tot Fwd Pkts"]["adv"]))

                # print("(max fwd pkt len, adv fwd max pkt len): ({}, {})".format(flow.flowStats.maxLen, fc["Fwd Pkt Len Max"]["adv"]))
                if flow.flowStats.maxLen != int(fc["Fwd Pkt Len Max"]["adv"]):
                    self.logger.warning("Fwd pkt len max differs (is, should be): ({}, {})".format(flow.flowStats.maxLen,
                                                                                                fc["Fwd Pkt Len Max"][
                                                                                                    "adv"]))

                # print("(min fwd pkt len, adv fwd min pkt len): ({}, {})".format(flow.flowStats.minLen, fc["Fwd Pkt Len Min"]["adv"]))
                if flow.flowStats.minLen != int(fc["Fwd Pkt Len Min"]["adv"]):
                    self.logger.warning(
                        "Fwd pkt len min differs (is, should be): ({}, {})".format(flow.flowStats.minLen,
                                                                                   fc["Fwd Pkt Len Min"][
                                                                                       "adv"]))


                if flow.biPkts:
                    biFK = flow.biFlowKey
                    self.flow_table.FT[biFK].calcPktLenStats()
                    if self.flow_table.FT[biFK].flowStats.maxLen > flow.flowStats.maxLen:
                        if self.flow_table.FT[biFK].flowStats.maxLen != int(fc["Pkt Len Max"]["adv"]):
                            self.logger.warning(
                                "Flow max pkt lens differ (is, should be): ({}, {})".format(
                                    self.flow_table.FT[biFK].flowStats.maxLen, fc["Pkt Len Max"]["adv"])
                            )

                    if self.flow_table.FT[biFK].flowStats.minLen < flow.flowStats.minLen:
                        if self.flow_table.FT[biFK].flowStats.minLen != int(fc["Pkt Len Min"]["adv"]):
                            self.logger.warning(
                                "Flow min pkt lens differ (is, should be): ({}, {})".format(
                                    self.flow_table.FT[biFK].flowStats.minLen, fc["Pkt Len Min"]["adv"])
                            )

                self.logger.info("----")


            # print("---")

        # print(self.config)

    def match_flow(self, flow, fc):
        match_counter_checker = 0
        assert_flag = False
        flowDur = round(flow.flowStats.flowDuration * 1000000)
        if flowDur != fc["Flow Duration"]["og"]:
            match_counter_checker += 1
            assert_flag = True
        if flow.biPkts:
            if len(flow.biPkts) != fc["Tot Bwd Pkts"]["og"]:
                match_counter_checker += 1
                assert_flag = True

        if assert_flag:
            if flow.biPkts and match_counter_checker != 2:
                print("ERROR! Match count checker != 2.  EXITING...")
                # self.print_feats_to_match(fc, flow)
                exit(-1)
            elif not flow.biPkts and match_counter_checker != 1:
                print("ERROR! Match count checker != 1.  EXITING...")
                # self.print_feats_to_match(fc, flow)
                exit(-1)
            return False
        return True
