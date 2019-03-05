from TransformClasses.Transform import TransPktLens, TransIATimes, TransDistUDP


class TransformationController:
    def __init__(self, config_flows, flowObj, biflow):          #pktLens = None, iaTimes = None, fixTS = None):
        self.flowConfig = config_flows
        self.flow = flowObj
        self.transObjList = [] # this list holds transformation objects
        self.splitFlowFlag = False
        self.biFlowFlag = biflow

    def runTransformations(self):
        for trans in self.transObjList:
            self.flow.calcPktLenStats()
            self.flow.calcPktIAStats()
            print("Transforming: {}".format(self.flow))
            trans.Process()
            print(self.flow.flowStats)
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        #print(self.flow)
        print("\n###################")


    def buildTransformations(self):
        if self.flow.flowKey[0] == 6 and len(self.flow.pkts) > 1:
            if "pktLens" in self.flowConfig:
                self.transObjList.append(TransPktLens(self.flow, self.flowConfig))
            if "iaTimes" in self.flowConfig:
                self.transObjList.append(TransIATimes(self.flow, self.flowConfig, self.biFlowFlag))
        elif self.flow.flowKey[0] == 17:
            print("check to transform udp flow by splitting")
            if "iaTimes" in self.flowConfig and len(self.flow.pkts) > 1:
                self.transObjList.append(TransIATimes(self.flow, self.flowConfig, self.biFlowFlag))
            if "numFlows" in self.flowConfig and self.flowConfig["numFlows"] != 1:
                self.transObjList.append(TransDistUDP(self.flow, self.flowConfig))
            #     self.splitFlowFlag = True
        if "test" in self.flowConfig:
            self.transObjList.append("testObj")


