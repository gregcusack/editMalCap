import logging


class TestFlowTransformation:
    def __init__(self, config, flow_table):
        self.config = config
        self.flow_table = flow_table
        logging.basicConfig(filename="logger-check-results.log",
                            format='%(message)s',
                            filemode='w')
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)
        self.percent_leeway = 0.05

    def check_flow_transformations(self):

        for tuple, flow in self.flow_table.FT.items():
            flag = False
            flow.calcPktLenStats()
            try:
                fc = self.config.flows[flow.flowKey]["features"]
                flag = True
            except KeyError:
                pass

            # print(flow)
            # # print("in test: {}".format(flow.flowStats.maxIA))
            flow.calcPktLenStats()
            flow.calcPktIAStats()

            if flag and self.match_flow(flow, fc):
                print("Testing Flow: {}".format(flow))
                self.logger.info("Testing Flow: {}".format(flow))
                self.logger.info("Testing Length Transformations...")
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

                self.logger.info("Testing Time Transformations...")
                if flow.adj_flow_dir != 0:
                    adv_flow_dur = flow.adj_flow_dir
                else:
                    adv_flow_dur = int(fc["Flow Duration"]["adv"]) / 1000000
                adv_fwd_iat_max = int(fc["Fwd IAT Max"]["adv"]) / 1000000
                adv_fwd_iat_min = int(fc["Fwd IAT Min"]["adv"]) / 1000000
                adv_flow_iat_max = int(fc["Flow IAT Max"]["adv"]) / 1000000
                adv_flow_iat_min = int(fc["Flow IAT Min"]["adv"]) / 1000000


                upper_range = adv_flow_dur * (1.00 + self.percent_leeway)
                lower_range = adv_flow_dur * (1.00 - self.percent_leeway)
                if flow.flowStats.flowDuration > upper_range or flow.flowStats.flowDuration < lower_range:
                    self.logger.warning(
                        "Total Duration differs by > {}% (is, should be) (s): ({}, {})".format(self.percent_leeway * 100,
                                                                                           flow.flowStats.flowDuration,
                                                                                                adv_flow_dur))

                # print("(max fwd pkt len, adv fwd max pkt len): ({}, {})".format(flow.flowStats.maxLen, fc["Fwd Pkt Len Max"]["adv"]))
                upper_range = adv_fwd_iat_max * (1.00 + self.percent_leeway)
                lower_range = adv_fwd_iat_max * (1.00 - self.percent_leeway)
                if flow.flowStats.maxIA > upper_range or flow.flowStats.maxIA < lower_range:
                    self.logger.warning(
                        "Fwd IAT max differs by > {}% (is, should be): ({}, {}) (s)".format(self.percent_leeway * 100,
                                                                                        flow.flowStats.maxIA,
                                                                                             adv_fwd_iat_max))

                # print("(min fwd pkt len, adv fwd min pkt len): ({}, {})".format(flow.flowStats.minLen, fc["Fwd Pkt Len Min"]["adv"]))
                upper_range = adv_fwd_iat_min * (1.00 + self.percent_leeway)
                lower_range = adv_fwd_iat_min * (1.00 - self.percent_leeway)
                if flow.flowStats.minIA > upper_range or flow.flowStats.minIA < lower_range:
                    self.logger.warning(
                        "Fwd IAT min min differs by > {}% (is, should be): ({}, {}) (s)".format(self.percent_leeway * 100,
                                                                                           flow.flowStats.minIA,
                                                                                                adv_fwd_iat_min))

                if flow.biPkts:
                    biFK = flow.biFlowKey
                    print("bipkt start")
                    self.flow_table.FT[biFK].calcPktIAStats()
                    print("bipkt end")
                    if self.flow_table.FT[biFK].flowStats.maxIA > flow.flowStats.maxIA:
                        upper_range = adv_flow_iat_max * (1.00 + self.percent_leeway)
                        lower_range = adv_flow_iat_max * (1.00 - self.percent_leeway)
                        if self.flow_table.FT[biFK].flowStats.maxIA > upper_range or \
                                self.flow_table.FT[biFK].flowStats.maxIA < lower_range:
                            self.logger.warning(
                                "Flow IAT max differs by >{}% (is, should be): ({}, {}) (s)".format(
                                    self.percent_leeway * 100,
                                    self.flow_table.FT[biFK].flowStats.maxIA, adv_flow_iat_max)
                            )

                    if self.flow_table.FT[biFK].flowStats.minIA < flow.flowStats.minIA:
                        upper_range = adv_flow_iat_min * (1.00 + self.percent_leeway)
                        lower_range = adv_flow_iat_min * (1.00 - self.percent_leeway)
                        if self.flow_table.FT[biFK].flowStats.minIA > upper_range or \
                                self.flow_table.FT[biFK].flowStats.minIA < lower_range:
                            self.logger.warning(
                                "Flow IAT min differs by > {}% (is, should be): ({}, {}) (s)".format(
                                    self.percent_leeway * 100,
                                    self.flow_table.FT[biFK].flowStats.minIA, adv_flow_iat_min)
                            )

                self.logger.info("Testing Flags...")



                flow.flowStats.get_flag_counts(flow.pkts)
                if flow.biPkts:
                    self.flow_table.FT[flow.biFlowKey].flowStats.get_flag_counts(flow.biPkts)

                    tot_flags = flow.flowStats.urgFlags + self.flow_table.FT[flow.biFlowKey].flowStats.urgFlags
                    if tot_flags != int(fc["URG Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow URG Flags differ (is, should be): ({}, {}) (s)".format(
                                tot_flags, int(fc["URG Flag Cnt"]["adv"]))
                        )
                    tot_flags = flow.flowStats.finFlags + self.flow_table.FT[flow.biFlowKey].flowStats.finFlags
                    if tot_flags != int(fc["FIN Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow FIN Flags differ (is, should be): ({}, {}) (s)".format(
                                tot_flags, int(fc["FIN Flag Cnt"]["adv"]))
                        )
                    tot_flags = flow.flowStats.synFlags + self.flow_table.FT[flow.biFlowKey].flowStats.synFlags
                    if tot_flags != int(fc["SYN Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow SYN Flags differ (is, should be): ({}, {}) (s)".format(
                                tot_flags, int(fc["SYN Flag Cnt"]["adv"]))
                        )
                    tot_flags = flow.flowStats.rstFlags + self.flow_table.FT[flow.biFlowKey].flowStats.rstFlags
                    if tot_flags != int(fc["RST Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow RST Flags differ (is, should be): ({}, {}) (s)".format(
                                tot_flags, int(fc["RST Flag Cnt"]["adv"]))
                        )
                    tot_flags = flow.flowStats.pshFlags + self.flow_table.FT[flow.biFlowKey].flowStats.pshFlags
                    if tot_flags != int(fc["PSH Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow PSH Flags differ (is, should be): ({}, {}) (s)".format(
                                tot_flags, int(fc["PSH Flag Cnt"]["adv"]))
                        )
                    tot_flags = flow.flowStats.ackFlags + self.flow_table.FT[flow.biFlowKey].flowStats.ackFlags
                    if tot_flags != int(fc["ACK Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow ACK Flags differ (is, should be): ({}, {}) (s)".format(
                                tot_flags, int(fc["ACK Flag Cnt"]["adv"]))
                        )
                    tot_flags = flow.flowStats.eceFlags + self.flow_table.FT[flow.biFlowKey].flowStats.eceFlags
                    if tot_flags != int(fc["ECE Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow ECE Flags differ (is, should be): ({}, {}) (s)".format(
                                tot_flags, int(fc["ECE Flag Cnt"]["adv"]))
                        )
                    tot_flags = flow.flowStats.cweFlags + self.flow_table.FT[flow.biFlowKey].flowStats.cweFlags
                    if tot_flags != int(fc["CWE Flag Count"]["adv"]):
                        self.logger.warning(
                            "Flow CWE Flags differ (is, should be): ({}, {}) (s)".format(
                                tot_flags, int(fc["CWE Flag Count"]["adv"]))
                        )
                else:
                    if flow.flowStats.urgFlags != int(fc["URG Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow URG Flags differ (is, should be): ({}, {}) (s)".format(
                                flow.flowStats.urgFlags, int(fc["URG Flag Cnt"]["adv"]))
                        )
                    if flow.flowStats.finFlags != int(fc["FIN Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow FIN Flags differ (is, should be): ({}, {}) (s)".format(
                                flow.flowStats.finFlags, int(fc["FIN Flag Cnt"]["adv"]))
                        )
                    if flow.flowStats.synFlags != int(fc["SYN Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow SYN Flags differ (is, should be): ({}, {}) (s)".format(
                                flow.flowStats.synFlags, int(fc["SYN Flag Cnt"]["adv"]))
                        )
                    if flow.flowStats.rstFlags != int(fc["RST Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow RST Flags differ (is, should be): ({}, {}) (s)".format(
                                flow.flowStats.rstFlags, int(fc["RST Flag Cnt"]["adv"]))
                        )
                    if flow.flowStats.pshFlags != int(fc["PSH Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow PSH Flags differ (is, should be): ({}, {}) (s)".format(
                                flow.flowStats.pshFlags, int(fc["PSH Flag Cnt"]["adv"]))
                        )
                    if flow.flowStats.ackFlags != int(fc["ACK Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow ACK Flags differ (is, should be): ({}, {}) (s)".format(
                                flow.flowStats.ackFlags, int(fc["ACK Flag Cnt"]["adv"]))
                        )
                    if flow.flowStats.eceFlags != int(fc["ECE Flag Cnt"]["adv"]):
                        self.logger.warning(
                            "Flow ECE Flags differ (is, should be): ({}, {}) (s)".format(
                                flow.flowStats.eceFlags, int(fc["ECE Flag Cnt"]["adv"]))
                        )
                    if flow.flowStats.cweFlags != int(fc["CWE Flag Count"]["adv"]):
                        self.logger.warning(
                            "Flow CWE Flags differ (is, should be): ({}, {}) (s)".format(
                                flow.flowStats.cweFlags, int(fc["CWE Flag Count"]["adv"]))
                        )


                self.logger.info("Testing Fwd Window Bytes")
                if flow.pkts[0].tcp_window != int(fc["Init Fwd Win Byts"]["adv"]):
                    self.logger.warning(
                        "Init Window Bytes differ (is, should be): ({}, {}) (s)".format(
                            flow.pkts[0].tcp_window, int(fc["Init Fwd Win Byts"]["adv"]))
                    )

                self.logger.info("----")


            # print("---")

        # print(self.config)

    def match_flow(self, flow, fc):
        match_counter_checker = 0
        assert_flag = False
        # flowDur = round(flow.flowStats.flowDuration * 1000000)
        flowDur = round(flow.oldFlowDuration * 1000000)
        if flowDur != fc["Flow Duration"]["og"]:
            match_counter_checker += 1
            assert_flag = True
            return False
        if flow.biPkts:
            if len(flow.biPkts) != fc["Tot Bwd Pkts"]["og"]:
                match_counter_checker += 1
                assert_flag = True
                return False
        return True