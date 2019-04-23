from TransformClasses.Transform import TransPktLens, TransIATimes, TransDistUDP, LengthTransform, TimeTransform, FlagTransform


class TransformationController:
    def __init__(self, config_flows, flowObj, biflow):          #pktLens = None, iaTimes = None, fixTS = None):
        self.flowConfig = config_flows
        self.flow = flowObj
        self.transObjList = [] # this list holds transformation objects
        self.splitFlowFlag = False
        self.biFlowFlag = biflow

    def runTransformations(self):
        # print("transobjlist: {}".format(self.transObjList))
        for trans in self.transObjList:
            self.flow.calcPktLenStats()
            self.flow.calcPktIAStats()
            # print("pre process flow {}".format(self.flow))
            # if self.biFlowFlag:
            #     print("pre process biflow: {}".format(len(self.flow.biPkts)))
            trans.Process()
            # print("Flow tuple: {}".format(self.flow.flowKey))
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()

        print("FLOW: {}".format(self.flow))
        if self.biFlowFlag:
            print("BIFLOW: {}, {}".format(self.flow.biFlowKey, len(self.flow.biPkts)))
        else:
            print("NO BIFLOW")
        # print("flow after trans: {}".format(self.flow))
        print("\n#####################")


    def buildTransformations(self):
        # print("flow config: {}".format(self.flowConfig))

        fc = self.flowConfig["features"]

        if self.flow.flowKey[0] == 6:
            if "Tot Fwd Pkts" in fc or "Fwd Pkt Len Max" in fc or "Fwd Pkt Len Min" in fc or "Pkt Len Min" in fc or "Pkt Len Max" in fc:
                self.transObjList.append(LengthTransform(self.flow, self.flowConfig["features"], self.biFlowFlag))
            # if "Flow Duration" in fc or "Flow IAT Max" in fc or "Flow IAT Min" in fc or "Fwd IAT Max" in fc or "Fwd IAT Min" in fc:
            #     self.transObjList.append(TimeTransform(self.flow, self.flowConfig, self.biFlowFlag))
            # if "Fwd PSH Flags" in fc or "URG Flag Cnt" in fc or "FIN Flag Cnt" in fc or "CWE Flag Count" in fc:
            #     self.transObjList.append(FlagTransform(self.flow, self.flowConfig))

            # if "pktLens" in self.flowConfig:
            #     self.transObjList.append(TransPktLens(self.flow, self.flowConfig))
            # if "iaTimes" in self.flowConfig:
            #     self.transObjList.append(TransIATimes(self.flow, self.flowConfig, self.biFlowFlag))
        elif self.flow.flowKey[0] == 17:
            print("check to transform udp flow by splitting")
            if "iaTimes" in self.flowConfig and len(self.flow.pkts) > 1:
                self.transObjList.append(TransIATimes(self.flow, self.flowConfig, self.biFlowFlag))
            if "numFlows" in self.flowConfig and self.flowConfig["numFlows"] != 1:
                self.transObjList.append(TransDistUDP(self.flow, self.flowConfig))
            #     self.splitFlowFlag = True
        # if "test" in self.flowConfig:
        #     self.transObjList.append("testObj")





