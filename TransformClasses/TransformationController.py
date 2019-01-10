from TransformClasses.Transform import TransPktLens, TransIATimes


class TransformationController:
    def __init__(self, config_flows, flowObj):          #pktLens = None, iaTimes = None, fixTS = None):
        self.flowConfig = config_flows
        self.flow = flowObj
        self.transObjList = [] # this list holds transformation objects

    def runTransformations(self):
        for trans in self.transObjList:
            trans.Process()
        #print(self.flow)
        #print(self.flow.flowStats)

    def buildTransformations(self):
        if "pktLens" in self.flowConfig:
            self.transObjList.append(TransPktLens(self.flow, self.flowConfig))
        if "iaTimes" in self.flowConfig:
            self.transObjList.append(TransIATimes(self.flow, self.flowConfig))
        if "test" in self.flowConfig:
            self.transObjList.append("testObj")


