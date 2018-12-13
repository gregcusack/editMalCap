#from TransPktLens import TransPktLens
#from TransIATimes import TransIATimes

from TransformationController import TransPktLens, TransIATimes

class Transform:
    def __init__(self, config_flows, flowPktList):          #pktLens = None, iaTimes = None, fixTS = None):
        self.flowConfig = config_flows
        self.pktList = flowPktList
        self.transObjList = [] # this list holds transformation objects

    def runTransformations(self):
        for trans in self.transObjList:
            trans.Process()

    def buildTransformations(self):
        if "pktLens" in self.flowConfig:
            #self.transPktLens = TransPktLens()
            self.transObjList.append(TransPktLens(self.pktList))
        if "iaTimes" in self.flowConfig:
            #self.transIATimes = TransIATimes()
            self.transObjList.append(TransIATimes(self.pktList))
        if "test" in self.flowConfig:
            #self.transTest = "testObj"
            self.transObjList.append("testObj")