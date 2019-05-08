import copy


class Injector:
    def __init__(self, flowObj, config, logger, flowtable):
        self.flow = flowObj
        self.logger = logger
        self.config = config
        self.flagQueue = []
        self.FT = flowtable

    def inject_one(self, pkt, size_payload):
        if size_payload > 1400:
            size_payload = 1400
        self.logger.info("inject_one() with payload size: {}".format(size_payload))
        injectPacket = copy.deepcopy(pkt)

        # self.flow.flowStats.get_flag_counts(self.flow.pkts)
        # flags = self.get_top_flags()
        # self.update_flag_queue()            # re-sort flag queue

        flags = self.get_flags()

        self.init_pkt(injectPacket, flags)
        injectPacket.prune()
        injectPacket.set_pload(size_payload)

        self.flow.pkts.append(injectPacket)

    def inject_many(self, pkt, tot_fwd_pkts, fwd_pkt_len_max, fwd_pkt_len_min):
        if fwd_pkt_len_max > 1400:
            fwd_pkt_len_max = 1400
        self.logger.info("inject_many()")
        dummy_pkt = copy.deepcopy(pkt)

        flags = self.get_flags()

        self.init_pkt(dummy_pkt, flags)
        dummy_pkt.prune()

        inj = 0     # dictates if we inject one extra packet

        if self.flow.flowStats.maxLen < fwd_pkt_len_max:
            self.generate_and_inject(dummy_pkt, fwd_pkt_len_max)
            inj = 1

        for i in range(int(tot_fwd_pkts - self.flow.flowStats.flowLen - inj)):
            self.generate_and_inject(dummy_pkt, fwd_pkt_len_min)


    def init_pkt(self, pkt, flags):
        if flags:
            pkt.set_flags(flags)
        else:
            pkt.unset_flags()
        # pkt.tcp_chksum = 0x00
        # pkt.ip_chksum = 0x00

    def generate_and_inject(self, dummy_pkt, pload_len):
        injectPacket = copy.deepcopy(dummy_pkt)

        flags = self.get_flags()
        # self.update_flag_queue()  # re-sort flag queue

        self.init_pkt(dummy_pkt, flags)
        injectPacket.set_pload(pload_len)  # create pkt with len == min_pkt_len
        self.flow.pkts.append(injectPacket)


    def get_flags(self):
        self.flow.flowStats.get_flag_counts(self.flow.pkts)
        if self.flow.biPkts:
            self.FT[self.flow.biFlowKey].flowStats.get_flag_counts(self.flow.biPkts)
        self.update_flag_queue()
        flags = self.get_top_flags()
        return flags

    def get_top_flags(self):
        flags = ""
        for flag in self.flagQueue:
            if flag[0] > 0:
                flags += flag[1]
        # print("flags to inject: {}".format(flags))
        return flags

    # def update_flag_queue(self):
    #     self.flow.flowStats.flagQueue.sort(reverse=True)

    def update_flag_queue(self):
        self.flagQueue = []

        if self.flow.biPkts:
            self.flagQueue.append((self.config["FIN Flag Cnt"]["adv"] - self.flow.flowStats.finFlags
                                   - self.FT[self.flow.biFlowKey].flowStats.finFlags, "F"))
            self.flagQueue.append((self.config["SYN Flag Cnt"]["adv"] - self.flow.flowStats.synFlags
                                   - self.FT[self.flow.biFlowKey].flowStats.synFlags, "S"))
            self.flagQueue.append((self.config["RST Flag Cnt"]["adv"] - self.flow.flowStats.rstFlags
                                   - self.FT[self.flow.biFlowKey].flowStats.rstFlags, "R"))
            self.flagQueue.append((self.config["PSH Flag Cnt"]["adv"] - self.flow.flowStats.pshFlags
                                   - self.FT[self.flow.biFlowKey].flowStats.pshFlags, "P"))
            self.flagQueue.append((self.config["ACK Flag Cnt"]["adv"] - self.flow.flowStats.ackFlags
                                   - self.FT[self.flow.biFlowKey].flowStats.ackFlags, "A"))
            self.flagQueue.append((self.config["URG Flag Cnt"]["adv"] - self.flow.flowStats.urgFlags
                                   - self.FT[self.flow.biFlowKey].flowStats.urgFlags, "U"))
            self.flagQueue.append((self.config["ECE Flag Cnt"]["adv"] - self.flow.flowStats.eceFlags
                                   - self.FT[self.flow.biFlowKey].flowStats.eceFlags, "E"))
            self.flagQueue.append((self.config["CWE Flag Count"]["adv"] - self.flow.flowStats.cweFlags
                                   - self.FT[self.flow.biFlowKey].flowStats.cweFlags, "C"))
        else:
            self.flagQueue.append((self.config["FIN Flag Cnt"]["adv"] - self.flow.flowStats.finFlags, "F"))
            self.flagQueue.append((self.config["SYN Flag Cnt"]["adv"] - self.flow.flowStats.synFlags, "S"))
            self.flagQueue.append((self.config["RST Flag Cnt"]["adv"] - self.flow.flowStats.rstFlags, "R"))
            self.flagQueue.append((self.config["PSH Flag Cnt"]["adv"] - self.flow.flowStats.pshFlags, "P"))
            self.flagQueue.append((self.config["ACK Flag Cnt"]["adv"] - self.flow.flowStats.ackFlags, "A"))
            self.flagQueue.append((self.config["URG Flag Cnt"]["adv"] - self.flow.flowStats.urgFlags, "U"))
            self.flagQueue.append((self.config["ECE Flag Cnt"]["adv"] - self.flow.flowStats.eceFlags, "E"))
            self.flagQueue.append((self.config["CWE Flag Count"]["adv"] - self.flow.flowStats.cweFlags, "C"))

        self.flagQueue.sort(reverse = True)