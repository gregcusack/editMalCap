from TransformClasses.Transform import TransPktLens, TransIATimes, TransSplitPkts


class TransformationController:
    def __init__(self, config_flows, flowObj):          #pktLens = None, iaTimes = None, fixTS = None):
        self.flowConfig = config_flows
        self.flow = flowObj
        self.transObjList = [] # this list holds transformation objects
        self.splitFlowFlag = False

    def runTransformations(self):
        for trans in self.transObjList:
            trans.Process()
        #print(self.flow)
        print("\n###################")
        print(self.flow.flowStats)

    def buildTransformations(self):
        if "pktLens" in self.flowConfig:
            self.transObjList.append(TransPktLens(self.flow, self.flowConfig))
        if "iaTimes" in self.flowConfig:
            self.transObjList.append(TransIATimes(self.flow, self.flowConfig))
        if "numFlows" in self.flowConfig and self.flowConfig["numFlows"] != 1:
            self.transObjList.append(TransSplitPkts(self.flow, self.flowConfig))
            self.splitFlowFlag = True
        if "test" in self.flowConfig:
            self.transObjList.append("testObj")


