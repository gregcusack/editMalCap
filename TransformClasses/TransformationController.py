from TransformClasses.Transform import TransPktLens, TransIATimes, TransDistUDP


class TransformationController:
    def __init__(self, config_flows, flowObj):          #pktLens = None, iaTimes = None, fixTS = None):
        self.flowConfig = config_flows
        self.flow = flowObj
        self.transObjList = [] # this list holds transformation objects
        self.splitFlowFlag = False

    def runTransformations(self):
        for trans in self.transObjList:
            trans.Process()
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        #print(self.flow)
        print("\n###################")
        print(self.flow.flowStats)

    def buildTransformations(self):
        if self.flow.flowKey[0] == 6:
            if "pktLens" in self.flowConfig:
                self.transObjList.append(TransPktLens(self.flow, self.flowConfig))
            if "iaTimes" in self.flowConfig:
                self.transObjList.append(TransIATimes(self.flow, self.flowConfig))
        elif self.flow.flowKey[0] == 17:
            print("check to transform udp flow by splitting")
            if "numFlows" in self.flowConfig and self.flowConfig["numFlows"] != 1:
                self.transObjList.append(TransDistUDP(self.flow, self.flowConfig))
            #     self.splitFlowFlag = True
        if "test" in self.flowConfig:
            self.transObjList.append("testObj")


