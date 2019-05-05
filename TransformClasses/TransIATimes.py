

MAX_PKT_LOOPS = 6
MAX_SPLIT_PKT = 6
MAX_FRAME_SIZE = 3000
MAX_PKT_IAT_LOOPS = 3

class TransIATimes():
    def __init__(self, flowObj, config, logger, biFlowFlag):
        self.flow = flowObj
        self.config = config
        self.logger = logger

        self.biFlowFlag = biFlowFlag
        # self.flow.get_old_flow_duration()
        # Times are in us

        self.og_flow_dur = self.config["Flow Duration"]["og"] / 1000000
        self.adv_flow_dur = self.config["Flow Duration"]["adv"] / 1000000
        self.og_flow_iat_max = self.config["Flow IAT Max"]["og"] / 1000000
        self.adv_flow_iat_max = self.config["Flow IAT Max"]["adv"] / 1000000
        self.og_flow_iat_min = self.config["Flow IAT Min"]["og"] / 1000000
        self.adv_flow_iat_min = self.config["Flow IAT Min"]["adv"] / 1000000
        self.og_fwd_iat_max = self.config["Fwd IAT Max"]["og"] / 1000000
        self.adv_fwd_iat_max = self.config["Fwd IAT Max"]["adv"] / 1000000
        self.og_fwd_iat_min = self.config["Fwd IAT Min"]["og"] / 1000000
        self.adv_fwd_iat_min = self.config["Fwd IAT Min"]["adv"] / 1000000
        self.og_fwd_iat_mean = self.config["Fwd IAT Mean"]["og"] / 1000000
        self.adv_fwd_iat_mean = self.config["Fwd IAT Mean"]["adv"] / 1000000
        self.og_fwd_iat_std = self.config["Fwd IAT Std"]["og"] / 1000000
        self.adv_fwd_iat_std = self.config["Fwd IAT Std"]["adv"] / 1000000

    def process_increase_duration_F_F(self, directions, toextend):
        self.logger.info("F -> F adv_dur > og_dur")

        self.flow.pkts[self.flow.flowStats.flowLen - 1].ts += toextend

        if self.flow.pkts[self.flow.flowStats.flowLen - 1].ts - \
                self.flow.pkts[self.flow.flowStats.flowLen - 2].ts > self.adv_fwd_iat_max:
            # print("max iAT time exceeded")
            self.flow.calcPktIAStats()

            self.distribute_create_min_max_iat_inc(directions[1])  # for increasing flow duration
        else:
            self.logger.info(self.flow.pkts[0].ts - self.flow.pkts[self.flow.flowStats.flowLen - 1].ts)
            self.logger.info("max IAT not exceeded, all good")
            # print("NEED TO CREATE MIN IAT!")

    def process_increase_duration_F_B(self, directions, toextend):
        self.logger.info("F -> B adv_dur > og_dur")
        toextend = self.adv_flow_dur - self.og_flow_dur
        # print(toextend)
        self.flow.biPkts[len(self.flow.biPkts) - 1].ts += toextend

        if self.flow.pkts[self.flow.flowStats.flowLen - 1].ts - \
                self.flow.pkts[self.flow.flowStats.flowLen - 2].ts > self.adv_fwd_iat_max:
            self.logger.info("max iAT time exceeded")
            self.flow.calcPktIAStats()

            self.distribute_create_min_max_iat_inc(directions[1])  # for increasing flow duration
        else:
            # print(self.flow.pkts[0].ts - self.flow.pkts[self.flow.flowStats.flowLen - 1].ts)
            self.logger.info("max IAT not exceeded, all good")
            self.logger.info("NEED TO CREATE MIN IAT!")

    def process_decrease_duration_F_F(self, directions, toreduce):
        # print("flow_dur new 0: {}".format(self.flow.pkts[self.flow.flowStats.flowLen - 1].ts - self.flow.pkts[0].ts))
        pkt_N_old_ts = self.flow.pkts[self.flow.flowStats.flowLen - 1].ts

        self.flow.pkts[self.flow.flowStats.flowLen - 1].ts -= toreduce
        # print("flow_dur new 01: {}".format(self.flow.pkts[self.flow.flowStats.flowLen - 1].ts - self.flow.pkts[0].ts))

        self.logger.info("toreduce: {}".format(toreduce))
        self.distribute_create_min_max_iat_dec(pkt_N_old_ts, directions[1])

    def process_decrease_duration_F_B(self, directions, toreduce):
        pkt_N_old_ts = self.flow.pkts[self.flow.flowStats.flowLen - 1].ts
        biPkt_N_old_ts = self.flow.biPkts[len(self.flow.biPkts) - 1].ts
        self.flow.biPkts[len(self.flow.biPkts) - 1].ts -= toreduce

        prev_dur = (biPkt_N_old_ts - self.flow.pkts[0].ts)
        cur_dur = (self.flow.biPkts[len(self.flow.biPkts) - 1].ts - self.flow.pkts[0].ts)

        fraction_reduced = (prev_dur - cur_dur) / prev_dur
        # print("fraction reduced (F,B): {}".format(fraction_reduced))
        self.distribute(fraction_reduced, False, directions[1])
        self.flow.getDiffs()

        self.distribute_create_min_max_iat_dec(pkt_N_old_ts, directions[1])

    def process_noBiPkts(self):
        self.flow.get_1D_diffs()
        self.logger.info("No BiPkt, distribute")
        if self.adv_flow_dur > self.og_flow_dur:
            toextend = self.adv_flow_dur - self.og_flow_dur
            self.flow.pkts[self.flow.flowStats.flowLen - 1].ts += toextend
            fraction_reduced = self.create_max("F")
            self.distribute_noBiPkt(fraction_reduced)
            self.create_min(fraction_reduced)

    def distribute_noBiPkt(self, fraction_reduced):
        if self.flow.flowStats.flowLen == 3:
            self.logger.info("can't distribute with no biPkt if flowlen < 3")
            return
        i = 2
        prev_ts = self.flow.pkts[1].ts
        while i < self.flow.flowStats.flowLen:
            self.flow.pkts[i].ts = prev_ts + (1 - fraction_reduced) * self.flow.diffs[i][1]
            prev_ts = self.flow.pkts[i].ts
            i += 1


    def distribute_create_min_max_iat_inc(self, last_pkt_dir):
        fraction_reduced = self.create_max(last_pkt_dir)
        self.distribute(fraction_reduced, True, last_pkt_dir)
        self.create_min(fraction_reduced)

    def distribute_create_min_max_iat_dec(self, pkt_N_old_ts, last_pkt_dir):
        fraction_reduced = self.create_max_dec(pkt_N_old_ts, last_pkt_dir)
        self.distribute(fraction_reduced, True, last_pkt_dir)
        # self.flow.calcPktIAStats()
        # print("new diffs: {}".format(self.flow.getDiffs()))
        self.create_min(fraction_reduced)

    def create_max_dec(self, pkt_N_old_ts, last_pkt_dir):
        if self.flow.flowStats.flowLen == 2:
            # print("already set flow duration, can't change min/max with flow of only 2 pkts")
            return
        num_flow_pkts = self.flow.flowStats.flowLen
        pkt_0 = self.flow.pkts[0]
        pkt_1 = self.flow.pkts[1]
        pkt_N = self.flow.pkts[num_flow_pkts - 1]  # this was pkt pushed in to match flow dur

        if last_pkt_dir == "B":
            diff = self.flow.biPkts[len(self.flow.biPkts) - 1].ts - pkt_N.ts
            toMaxIAT = self.adv_flow_dur - (pkt_1.ts - pkt_0.ts) - diff         # not exact but gets close
        else:
            toMaxIAT = self.adv_fwd_iat_max - (pkt_1.ts - pkt_0.ts)
            pkt_1.ts += toMaxIAT

        prev_diff = pkt_N_old_ts - pkt_1.ts

        if pkt_1.ts > pkt_N.ts:
            self.logger.error("Error, max IAT exceeds flow duration.  Exiting...")
            # exit(-1)

        cur_diff = pkt_N.ts - pkt_1.ts
        if cur_diff < 0:
            self.logger.error("Error! pkt_1 is past pkt_N...should not happen.  Exiting...")
            # exit(-1)

        fraction_reduced = (prev_diff - cur_diff) / prev_diff

        return fraction_reduced
        # print(fraction_reduced)

    def create_max(self, last_pkt_dir):
        if self.flow.flowStats.flowLen == 2:
            print("already set flow duration, can't change min/max with flow of only 2 pkts")
            return
        num_flow_pkts = self.flow.flowStats.flowLen
        pkt_0 = self.flow.pkts[0]
        pkt_1 = self.flow.pkts[1]
        pkt_N = self.flow.pkts[num_flow_pkts - 1] # this was pkt pushed out to match flow dur

        toMaxIAT = self.adv_fwd_iat_max - (pkt_1.ts - pkt_0.ts)
        if last_pkt_dir == "B" and pkt_1.ts + toMaxIAT > pkt_N.ts:
            self.logger.info("p1 create max shift past pkt_N...will reduce p1 shift")
            diff = self.flow.biPkts[len(self.flow.biPkts) - 1].ts - pkt_N.ts
            toMaxIAT = self.adv_flow_dur - (pkt_1.ts - pkt_0.ts) - diff         # not exact but gets close
        else:
            # toMaxIAT = self.adv_fwd_iat_max - (pkt_1.ts - pkt_0.ts)
            pkt_1.ts += toMaxIAT

        prev_diff = pkt_N.ts - pkt_1.ts

        # toMaxIAT = self.adv_fwd_iat_max - (pkt_1.ts - pkt_0.ts)
        # pkt_1.ts += toMaxIAT

        if pkt_1.ts > pkt_N.ts:
            self.logger.error("Error, max IAT exceeds flow duration.  Exiting...")
            # exit(-1)

        cur_diff = pkt_N.ts - pkt_1.ts
        if cur_diff < 0:
            self.logger.error("Error! pkt_1 is past pkt_N...should not happen.  Exiting...")
            # exit(-1)

        fraction_reduced = (prev_diff - cur_diff) / prev_diff
        return fraction_reduced
        # print(fraction_reduced)

    def distribute(self, fraction_reduced, max_created, last_pkt_dir):
        i = j = k = 0
        f_count = 0
        prev_ts = None
        prev_dir = self.flow.diffs[0][0]  # TODO: make diff list a list of namedtuples!
        if prev_dir == "F":
            prev_ts = self.flow.pkts[0].ts
            f_count += 1
            i += 1
        elif prev_dir == "B":
            prev_ts = self.flow.biPkts[0].ts
            j += 1
        elif prev_dir == "S":
            print("ERROR? FLOW STARTS AT SAME TIME?!?!?! in updateBiTS()")
            print("Exiting...")
            exit(-1)
            # i += 1
            # j += 1
        else:
            print("ERROR! updateBiTS() error!")
            exit(-1)
        k += 1

        # print("i: {}, j: {}, k: {}".format(i,j,k))

        lastFDiffIndex = None
        # flag = False
        # first_flag = True
        # print(len(self.flow.diffs))
        # print("total flow len: {}".format(self.flow.flowStats.flowLen))
        while k < len(self.flow.diffs):
            if last_pkt_dir == "F":
                if i == self.flow.flowStats.flowLen - 1:  # this is only good if end with F
                    break
            elif last_pkt_dir == "B":
                if j == len(self.flow.biPkts) - 1:
                    break
            if max_created:
                if self.flow.diffs[k][0] == "F":
                    prev_ts = self.flow.pkts[i].ts
                    f_count += 1
                    i += 1
                    if f_count == 2: # reached
                        max_created = False
                elif self.flow.diffs[k][0] == "B":
                    prev_ts = self.flow.biPkts[j].ts
                    j += 1
                elif self.flow.diffs[k][0] == "S":
                    prev_ts = self.flow.pkts[i].ts
                    i += 1
                    j += 1
                k += 1
            elif not max_created:
                # print(i,j,k,f_count, self.flow.diffs[k][0])
                if self.flow.diffs[k][0] == "F":
                    self.flow.pkts[i].ts = prev_ts + (1 - fraction_reduced) * self.flow.diffs[k][1]
                    prev_ts = self.flow.pkts[i].ts
                    i += 1
                elif self.flow.diffs[k][0] == "B":
                    self.flow.biPkts[j].ts = prev_ts + (1 - fraction_reduced) * self.flow.diffs[k][1]
                    prev_ts = self.flow.biPkts[j].ts
                    j += 1
                elif self.flow.diffs[k][0] == "S":
                    self.flow.pkts[i].ts = prev_ts + (1 - fraction_reduced) * self.flow.diffs[k][1]
                    self.flow.biPkts[j].ts = prev_ts + (1 - fraction_reduced) * self.flow.diffs[k][1]
                    prev_ts = self.flow.pkts[i].ts
                    i += 1
                    j += 1
                k += 1

        # print(self.flow.diffs)
        # self.flow.getDiffs()
        # print(self.flow.diffs)

        # step = (self.flow.pkts[i].ts - self.flow.pkts[i - 1].ts) / num_flow_pkts

    def create_min(self, fraction_reduced):
        self.flow.calcPktIAStats()
        # print("Create MIN")
        self.logger.info("Create MIN")
        if self.flow.flowStats.flowLen <= 3:
            # print("Can't create min IAT since less than 3 pkts.")
            return
        if self.adv_fwd_iat_min < self.flow.flowStats.minIA:
            self.logger.info("decrease minIA")
            prev_ts = self.flow.pkts[1]
            i = 0
            b2b = 0
            prev_k = self.flow.diffs[0]
            minFlag = False
            for k in range(0, len(self.flow.diffs)):
                if self.flow.diffs[k][0] == "F":
                    i += 1
                    b2b += 1
                    if b2b == 2 and i > 2:
                        self.flow.pkts[i - 1].ts = self.flow.pkts[i - 2].ts + self.adv_fwd_iat_min
                        minFlag = True
                    else:
                        b2b = 1
                else:
                    b2b = 0
                k += 1
            if not minFlag:
                self.logger.info("No back to back pkts")
                if self.adv_fwd_iat_min == 0:
                    self.logger.info("Min == 0, can't get down to that")
                    self.flow.pkts[2].ts = self.flow.pkts[1].ts + 0.0000001

        elif self.adv_fwd_iat_min > self.flow.flowStats.minIA:
            # print("Increase minIA")
            self.logger.info("Increase minIA")
            flag = False
            prev_ts = self.flow.pkts[0]
            loops = 0
            while self.flow.flowStats.minIA < self.adv_fwd_iat_min and loops < MAX_PKT_IAT_LOOPS:
                for i in range(0, self.flow.flowStats.flowLen - 1):
                    # print("i: {}".format(i))
                    # print("dif: {}".format(self.flow.pkts[i + 1].ts - self.flow.pkts[i].ts))
                    if self.flow.pkts[i + 1].ts - self.flow.pkts[i].ts <= self.flow.flowStats.minIA:
                        # print("fwd min iA: {}".format(self.flow.pkts[i + 1].ts - self.flow.pkts[i].ts))
                        toextend = self.adv_fwd_iat_min - self.flow.flowStats.minIA
                        # print("flow min iA: {}".format(self.flow.flowStats.minIA))
                        # print("adv_iat_min: {}".format(self.adv_fwd_iat_min))
                        # print("toextend: {}".format(toextend))
                        self.flow.pkts[i + 1].ts += toextend
                        # print("fwd new min iA: {}".format(self.flow.pkts[i + 1].ts - self.flow.pkts[i].ts))
                        if i + 2 < self.flow.flowStats.flowLen and i != self.flow.flowStats.flowLen - 3 and self.flow.pkts[i + 1].ts > self.flow.pkts[i + 2].ts:
                            # print("bigger min IAT pushed past next pkt!")
                            self.logger.info("bigger min IAT pushed past next pkt!")
                            first_move_ts = self.flow.pkts[i + 1].ts
                            k = i + 2
                            while k != self.flow.flowStats.flowLen - 1:
                                # print("k: {}".format(k))
                                test = self.flow.pkts[k].ts + toextend
                                if test < self.flow.pkts[k + 1].ts and self.flow.pkts[k + 1].ts - test > self.adv_fwd_iat_min:
                                    self.flow.pkts[k].ts += toextend
                                    flag = True
                                    break
                                else:
                                    if k != self.flow.flowStats.flowLen - 2: # don't want to change last pkt
                                        self.flow.pkts[k].ts += toextend
                                    k += 1
                            if k == self.flow.flowStats.flowLen - 1:
                                # print("can't make min IAT!")
                                self.flow.pkts[i + 1].ts -= toextend
                                break
                        # else:
                        #     self.flow.calcPktIAStats()
                        #     if
                        #     print("Think we created min IA???")
                        #     for n in range(0, self.flow.flowStats.flowLen - 1):
                        #         print("n: {}".format(n))
                        #         if self.flow.pkts[n + 1].ts - self.flow.pkts[n].ts <= self.flow.flowStats.minIA+.001:
                        #             print("min ia: {}".format(self.flow.pkts[n + 1].ts - self.flow.pkts[n].ts))
                        #     break

                    if flag:
                        # print("min IAT created!")
                        break
                self.flow.calcPktIAStats()
                # print("about to loop min iA: {}".format(self.flow.flowStats.minIA))
                loops += 1

            # if loops == MAX_PKT_LOOPS:
            #     print("Max Pkt loops reached when created fwd min IAT!")

            self.flow.calcPktIAStats()
            if self.flow.flowStats.minIA != self.adv_fwd_iat_min:
                # print("can't reach minIA (is, should be): ({}, {})".format(self.flow.flowStats.minIA, self.adv_fwd_iat_min))
                self.logger.info("can't reach minIA (is, should be): ({}, {})".format(self.flow.flowStats.minIA, self.adv_fwd_iat_min))


    def get_start_and_end_pkt_directon(self):
        if not self.biFlowFlag:
            return "F", "F"

        ts_bi_end = self.flow.biPkts[len(self.flow.biPkts) - 1].ts
        ts_end = self.flow.pkts[len(self.flow.pkts) - 1].ts
        ts_bi_start = self.flow.biPkts[0].ts
        ts_start = self.flow.pkts[0].ts
        if ts_bi_end > ts_end:
            end_direction = "B"
        else:
            end_direction = "F"

        if ts_bi_start < ts_start:
            start_direction = "B"
        else:
            start_direction = "F"
        return start_direction, end_direction


    def updateBiTS(self):
        i = j = k = 0
        prev_ts = None
        prev_dir = self.flow.diffs[0][0]                # TODO: make diff list a list of namedtuples!
        if prev_dir == "F":
            prev_ts = self.flow.pkts[0].ts
            i += 1
        elif prev_dir == "B":
            prev_ts = self.flow.biPkts[0].ts
            j += 1
        elif prev_dir == "S":
            print("ERROR? FLOW STARTS AT SAME TIME?!?!?! in updateBiTS()")
            print("Exiting...")
            exit(-1)
            # i += 1
            # j += 1
        else:
            print("ERROR! updateBiTS() error!")
            exit(-1)
        k += 1

        # print("i: {}, j: {}, k: {}".format(i,j,k))

        lastFDiffIndex = None

        self.logger.info("update biTS diffs: {}".format(self.flow.diffs))
        while k < len(self.flow.diffs):
        #for dir in range(1,len(self.flow.diffs)):
            # print("k: {}".format(k))
            # print("sup")
            # print(self.flow.diffs)
            # print(self.flow.diffs[k][0])
            # print("ts diff: {}".format(self.flow.pkts[1].ts - self.flow.pkts[0].ts))
            if self.flow.diffs[k][0] == "B":
                count = 0
                bis = []
                while k < len(self.flow.diffs) and self.flow.diffs[k][0] == "B":
                    # print("k: {}".format(k))
                    # print(self.flow.)
                    # print("b looping")
                    count += 1
                    bis.append(j)
                    j += 1
                    k += 1
                # print(count)
                # if count == 0:
                #     count == 1
                # print(bis)
                # print("i: {}".format(i))
                # print("pkts: {}".format(self.flow.pkts))
                # TODO: if B is last pkt, then no step needed.  take all b packets and add
                if k != len(self.flow.diffs):   # at least one more F in biflow
                    step = (self.flow.pkts[i].ts - self.flow.pkts[i-1].ts) / count
                    # print("step: {}".format(step))
                    #print(count)
                    m = 0
                    for n in bis:
                        #print("n: {}".format(n))
                        self.flow.biPkts[n].ts = self.flow.pkts[i-1].ts + step * m + step / 2
                        m += 1
                else: # signifies B is last pkt
                    if self.flow.pkts[i - 1].ts > self.flow.biPkts[bis[0]].ts:      # F pkt moved ahead of B after IAT trans
                        # TODO: move all bipkts whose index is in bis[] on other side of last F
                        # B0.ts = last_F.ts + (B0 - last_F.ts)
                        # B0.ts - last_F.ts is stored in diffs at
                        # print("need to move B pkts on other side of the last F")
                        p_ts = self.flow.pkts[i - 1].ts
                        for n in bis:
                            # print("lastfDiffIndex: {}".format(lastFDiffIndex))
                            self.flow.biPkts[n].ts = p_ts + self.flow.diffs[lastFDiffIndex][1]
                            p_ts = self.flow.biPkts[n].ts
                            lastFDiffIndex += 1
                    else:
                        self.logger.info("F didn't move to other side of B, so think we're good???")
                # print("len bis[]: {}".format(len(bis)))

            elif self.flow.diffs[k][0] == "F":
                prev_ts = self.flow.pkts[i].ts
                i += 1
                k += 1
                if i >= len(self.flow.pkts):
                    lastFDiffIndex = k
            else:
                # print("flow diffs: {}".format(self.flow.diffs[k][0]))
                prev_ts = self.flow.pkts[i].ts
                # print("F AND B AT SAME TIME!")
                i += 1
                j += 1
                k += 1
        self.flow.getDiffs()
        self.logger.info("post update biTS diffs: {}".format(self.flow.diffs))
