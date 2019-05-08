from TransformClasses.Transform import TransDistUDP, LengthTransform, TimeTransform, WindowTransform


class TransformationController:
    def __init__(self, config_flows, flowObj, biflow, logger, flowtable):          #pktLens = None, iaTimes = None, fixTS = None):
        self.flowConfig = config_flows
        self.flow = flowObj
        self.transObjList = [] # this list holds transformation objects
        self.splitFlowFlag = False
        self.biFlowFlag = biflow
        self.logger = logger
        self.FT = flowtable

    def runTransformations(self):
        # print("transobjlist: {}".format(self.transObjList))
        print("Processing flow: {}".format(self.flow))
        for trans in self.transObjList:
            self.flow.calcPktLenStats()
            self.flow.calcPktIAStats()
            # print("pre process flow stats: {}".format(self.flow.flowStats))
            # if self.biFlowFlag:
            #     print("pre process biflow: {}".format(len(self.flow.biPkts)))
            trans.Process()
            print("new flow stats: {}".format(self.flow.flowStats))
            # print("Flow tuple: {}".format(self.flow.flowKey))
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()

        self.logger.info("FLOW: {}".format(self.flow))
        if self.biFlowFlag:
            self.logger.info("BIFLOW: {}, {}".format(self.flow.biFlowKey, len(self.flow.biPkts)))
        else:
            self.logger.info("NO BIFLOW")
        # print("flow after trans: {}".format(self.flow))
        self.logger.info("\n#####################")
        print("\n#####################")


    def buildTransformations(self):
        # print("flow config: {}".format(self.flowConfig))

        fc = self.flowConfig["features"]

        if self.flow.flowKey[0] == 6:
            if fc["Tot Fwd Pkts"]["og"] != fc["Tot Fwd Pkts"]["adv"] or \
                fc["Fwd Pkt Len Max"]["og"] != fc["Fwd Pkt Len Max"]["adv"] or \
                fc["Fwd Pkt Len Min"]["og"] != fc["Fwd Pkt Len Min"]["adv"] or \
                fc["Pkt Len Min"]["og"] != fc["Pkt Len Min"]["adv"] or \
                fc["Pkt Len Max"]["og"] != fc["Pkt Len Max"]["adv"]:

                self.transObjList.append(LengthTransform(self.flow, self.flowConfig["features"], self.biFlowFlag, self.logger, self.FT))

            if fc["Flow Duration"]["og"] != fc["Flow Duration"]["adv"] or \
                fc["Flow IAT Max"]["og"] != fc["Flow IAT Max"]["adv"] or \
                fc["Flow IAT Min"]["og"] != fc["Flow IAT Min"]["adv"] or \
                fc["Fwd IAT Max"]["og"] != fc["Fwd IAT Max"]["adv"] or \
                fc["Fwd IAT Min"]["og"] != fc["Fwd IAT Min"]["adv"]:

                self.transObjList.append(TimeTransform(self.flow, self.flowConfig["features"], self.biFlowFlag, self.logger))

            if fc["Init Fwd Win Byts"]["og"] != fc["Init Fwd Win Byts"]["adv"]:
                self.transObjList.append(WindowTransform(self.flow, self.flowConfig["features"], self.logger))
            # if fc["Fwd PSH Flags"]["og"] != fc["Fwd PSH Flags"]["adv"] or \
            #     fc["Fwd URG Flags"]["og"] != fc["Fwd URG Flags"]["adv"] or \
            #     fc["URG Flag Cnt"]["og"] != fc["URG Flag Cnt"]["adv"] or \
            #     fc["FIN Flag Cnt"]["og"] != fc["FIN Flag Cnt"]["adv"] or \
            #     fc["SYN Flag Cnt"]["og"] != fc["SYN Flag Cnt"]["adv"] or \
            #     fc["RST Flag Cnt"]["og"] != fc["RST Flag Cnt"]["adv"] or \
            #     fc["PSH Flag Cnt"]["og"] != fc["PSH Flag Cnt"]["adv"] or \
            #     fc["ACK Flag Cnt"]["og"] != fc["ACK Flag Cnt"]["adv"] or \
            #     fc["ECE Flag Cnt"]["og"] != fc["ECE Flag Cnt"]["adv"] or \
            #     fc["CWE Flag Count"]["og"] != fc["CWE Flag Count"]["adv"]:
            #
            #     self.transObjList.append(FlagTransform(self.flow, self.flowConfig["features"], self.biFlowFlag, self.logger))


        elif self.flow.flowKey[0] == 17:
            self.logger.info("UDP FLOW!")
            self.logger.info("check to transform udp flow by splitting")
            return
            # if "iaTimes" in self.flowConfig and len(self.flow.pkts) > 1:
            #     self.transObjList.append(TransIATimes(self.flow, self.flowConfig, self.biFlowFlag))
            # if "numFlows" in self.flowConfig and self.flowConfig["numFlows"] != 1:
            #     self.transObjList.append(TransDistUDP(self.flow, self.flowConfig))






