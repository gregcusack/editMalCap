import copy


class Injector:
    def __init__(self, flowObj, logger):
        self.flow = flowObj
        self.logger = logger

    def inject_one(self, pkt, size_payload):
        self.logger.info("inject_one() with payload size: {}".format(size_payload))
        injectPacket = copy.deepcopy(pkt)

        self.init_pkt(injectPacket)
        injectPacket.prune()
        injectPacket.set_pload(size_payload)

        self.flow.pkts.append(injectPacket)

    def inject_many(self, pkt, tot_fwd_pkts, fwd_pkt_len_max, fwd_pkt_len_min):
        self.logger.info("inject_many()")

        dummy_pkt = copy.deepcopy(pkt)
        self.init_pkt(dummy_pkt)
        dummy_pkt.prune()

        inj = 0     # dictates if we inject one extra packet

        if self.flow.flowStats.maxLen < fwd_pkt_len_max:
            self.generate_and_inject(dummy_pkt, fwd_pkt_len_max)
            inj = 1

        for i in range(int(tot_fwd_pkts - self.flow.flowStats.flowLen - inj)):
            self.generate_and_inject(dummy_pkt, fwd_pkt_len_min)


    def init_pkt(self, pkt):
        pkt.set_flags("A")
        pkt.tcp_chksum = 0x00
        pkt.ip_chksum = 0x00

    def generate_and_inject(self, dummy_pkt, pload_len):
        injectPacket = copy.deepcopy(dummy_pkt)
        injectPacket.set_pload(pload_len)  # create pkt with len == min_pkt_len
        self.flow.pkts.append(injectPacket)



