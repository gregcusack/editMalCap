from FlowTable import FlowTable, FlowFilter
from TransPkt import TransPkt
from PktMerger import PktMerger
from Transform import Transform

class NetSploit:
    def __init__(self, config):             # this should be a map of our config file
        # try to keep this just objects
        self.flowTable = FlowTable()
        self.filter = FlowFilter(config.flows)
        self.pktMerger = PktMerger(config.merge_batch_size)
        self.config = config

    def Process(self, pkt):
        if self.filter.needsTrans(pkt.flow_tuple):
            print("Send packet for transformation")
            self.flowTable.procPkt(pkt)
            self.checkToTransform(pkt)
        else:
            print("No Transformation needed.  Sending to Pkt Merger")
            self.pktMerger.mergePkt(pkt)
            # need to send to Pkt Merger here

    # Check if thresholds reached and need to send pkt for Transformation
    def checkToTransform(self, pkt):
        toDelete = set()
        curPktTime = pkt.ts * 1000 # get current time in ms
        #print(self.flowTable.L_TS)
        # Using curPktTime to check how long it has been since each flow has seen a pkt
        for k, v in self.flowTable.L_TS.items():
            print("curPktTime - v: {}".format(curPktTime - v))
            if (curPktTime - v) >= self.config.time_since_last_pkt:
                self.transformFlow(k, "Timeout Reached")
                toDelete.add(k)

        # delete transformed flows (timeout case)
        if toDelete:
            for flowKey in toDelete:
                self.flowTable.delFlow(flowKey)

        # Make sure that we don't try to transform a flow we already transformed (and should have deleted)
        # This is just a testing mechanism.  Doesn't do anything else
        if (pkt.flow_tuple in toDelete) and (pkt.flow_tuple in self.flowTable.L_TS or pkt.flow_tuple in self.flowTable.FT):
            print("ERROR: Flow was not properly deleted! Offending key: {}".format(pkt.flow_tuple))
            exit(-1)

        # Check if pkt threshold reached
        if len(self.flowTable.FT[pkt.flow_tuple]) >= self.config.pkt_thresh:
            self.transformFlow(pkt.flow_tuple, "PktThresh Reached")
            self.flowTable.delFlow(pkt.flow_tuple)

    # Called in one of two cases:
    #   1) Time since last pkt received by flow exceeds user set value (config.time_since_last_pkt)
    #   2) # of pkts in flow exceeds user set value (config.PktThresh)
    def transformFlow(self, pkt_5_tuple, note=None):
        if note:
            print("Time to Transform!  Flow Tuple: {}. Note: {}".format(pkt_5_tuple, note))
        else:
            print("Time to Transform!  Flow Tuple: {}".format(pkt_5_tuple))

        _transform = Transform(self.config.flows[pkt_5_tuple], self.flowTable.FT[pkt_5_tuple])
        _transform.buildTransformations()
        _transform.runTransformations()
        #TODO: Transform Flow!  Call: TransPktLens.py
        #TODO: Transform Flow!  Call: TransIATimes.py
        #TODO: Fix Timestamps!  Call: FixTimestamps.py

        # Delete Flow from FlowTable
        #self.flowTable.delFlow(pkt_5_tuple)
