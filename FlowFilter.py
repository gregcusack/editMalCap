from TransPkt import TransPkt

class FlowFilter:
    def __init__(self, list):
        self.tuple_set = set(list)
        # print(type(self.tuple_set))
        # print(self.tuple_set)

    def proc_pkt(self, pkt):
        #pkt needs to be a TransPkt type
        if pkt.flow_tuple in self.tuple_set:
            return True
        return False