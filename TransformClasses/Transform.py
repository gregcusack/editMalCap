import copy
from FlowTable import FlowTable
import numpy as np
from math import ceil
from scapy.all import *
from TransformClasses.Splitter import Splitter
from TransformClasses.Merger import Merger
from TransformClasses.Injector import Injector
from scipy.stats import truncnorm
from math import ceil
from random import randint, uniform

MAX_PKT_LOOPS = 6
MAX_SPLIT_PKT = 6
MAX_FRAME_SIZE = 3000
MAX_PKT_IAT_LOOPS = 3

def get_truncnorm(mean=0, sd=1, low=0, upp=10):
    print("target iat (mean, std, min, max): ({}, {}, {}, {})".format(mean, sd, low, upp))
    return truncnorm((low - mean) / sd, (upp - mean) / sd, loc=mean, scale=sd)

class Transform:
    def __init__(self, flowObj, config, logger):
        self.flow = flowObj
        self.config = config
        self.logger = logger
        # print("transform create")
        #self.pktsToRemove = []

    def Process(self):
        raise NotImplementedError()

class LengthTransform(Transform):
    def __init__(self, flowObj, config, biFlowFlag, logger):
        Transform.__init__(self, flowObj, config, logger)
        self.biFlowFlag = biFlowFlag

        self.og_tot_fwd_pkts = self.config["Tot Fwd Pkts"]["og"]
        self.adv_tot_fwd_pkts = self.config["Tot Fwd Pkts"]["adv"]

        self.og_fwd_pkt_len_max = self.config["Fwd Pkt Len Max"]["og"]
        self.adv_fwd_pkt_len_max = self.config["Fwd Pkt Len Max"]["adv"]
        self.og_fwd_pkt_len_min = self.config["Fwd Pkt Len Min"]["og"]
        self.adv_fwd_pkt_len_min = self.config["Fwd Pkt Len Min"]["adv"]
        # print("Creating new LengthTransform Object")

    def Process(self):
        # return
        self.logger.info("processing Length Transformation: {}".format(self.flow))
        print("processing Length Transformation: {}".format(self.flow))
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        # print("LengthTransform Process()")
        # print("flow: {}".format(self.flow))

        if self.og_tot_fwd_pkts != self.adv_tot_fwd_pkts:
            if self.flow.flowStats.maxLen == 0:
                self.logger.info("max pkt length == 0.  Can't split.  Need to inject hella")
                injector = Injector(self.flow, self.logger)
                injector.inject_many(self.flow.pkts[len(self.flow.pkts) - 1],
                                     self.adv_tot_fwd_pkts, self.adv_fwd_pkt_len_max, self.adv_fwd_pkt_len_min)
            else:
                self.fixTotFwdPkts()
        elif self.og_tot_fwd_pkts == self.adv_tot_fwd_pkts:
            if self.flow.flowStats.maxLen < self.adv_fwd_pkt_len_max:
                self.logger.info("og and adv tot pkts the same.  Fixing max packet len")
                split = Splitter(self.flow, self.config, self.logger)
                index = split.create_max_packet_len()
                if index != -1:
                    self.logger.info("Able to set max packet length!")
                else:
                    self.logger.info("unable to set max pkt len")
            elif self.flow.flowStats.maxLen == self.adv_fwd_pkt_len_max:
                self.logger.info("max pkts same.")
            else:
                self.logger.info("cant set max pkt len.  config requires us to remove information")

        self.flow.calcPktLenStats()

        self.logger.info("after length transform stats: {}".format(self.flow.flowStats))


    def fixTotFwdPkts(self):
        self.logger.info("fixing Tot Fwd Pkts")

        if self.og_tot_fwd_pkts < self.adv_tot_fwd_pkts:
            split = Splitter(self.flow, self.config, self.logger)
            if self.og_fwd_pkt_len_max == self.adv_fwd_pkt_len_max:
                split.split_max_lens_eq()
            elif self.og_fwd_pkt_len_max < self.adv_fwd_pkt_len_max:
                self.logger.info("og pkt len max < adv pkt len max -- merge 2 then split")
                split.split_og_max_len_lt()
            else:
                self.logger.info("og pkt len max > adv pkt len max -- split then merge 2")
                split.split_og_max_len_gt()

            if self.flow.flowStats.minLen != self.adv_fwd_pkt_len_min:
                split.set_min_packet_length()
        else:                                                                       #og pkts > adv pkts -> so merge
            merge = Merger(self.flow, self.config, self.logger)
            self.logger.info("NEED TO MERGE PACKETS")


class TimeTransform(Transform):
    def __init__(self, flowObj, config, biFlowFlag, logger):
        Transform.__init__(self, flowObj, config, logger)
        self.biFlowFlag = biFlowFlag
        self.logger.info("creating new TimeTransform Object")

        # Times are in us
        self.og_flow_dur = self.config["Flow Duration"]["og"]           /   1000000
        self.adv_flow_dur = self.config["Flow Duration"]["adv"]         /   1000000
        self.og_flow_iat_max = self.config["Flow IAT Max"]["og"]        /   1000000
        self.adv_flow_iat_max = self.config["Flow IAT Max"]["adv"]      /   1000000
        self.og_flow_iat_min = self.config["Flow IAT Min"]["og"]        /   1000000
        self.adv_flow_iat_min = self.config["Flow IAT Min"]["adv"]      /   1000000
        self.og_fwd_iat_max = self.config["Fwd IAT Max"]["og"]          /   1000000
        self.adv_fwd_iat_max = self.config["Fwd IAT Max"]["adv"]        /   1000000
        self.og_fwd_iat_min = self.config["Fwd IAT Min"]["og"]          /   1000000
        self.adv_fwd_iat_min = self.config["Fwd IAT Min"]["adv"]        /   1000000
        self.og_fwd_iat_mean = self.config["Fwd IAT Mean"]["og"]        /   1000000
        self.adv_fwd_iat_mean = self.config["Fwd IAT Mean"]["adv"]      /   1000000
        self.og_fwd_iat_std = self.config["Fwd IAT Std"]["og"]          /   1000000
        self.adv_fwd_iat_std = self.config["Fwd IAT Std"]["adv"]        /   1000000


    def Process(self):
        # print(len(self.flow.pkts))
        # self.flow.pkts = self.flow.pkts[:-3]# = self.flow.pkts[1:]
        # print(len(self.flow.pkts))
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        self.logger.info("TimeTransform Process()")
        print("TimeTransform Process()")


        if self.biFlowFlag:
            if self.flow.flowStats.flowLen == 1:
                print("can't change flow length of flow with 1 pkt")
                return
            self.flow.getDiffs()
            print(len(self.flow.diffs))
            if self.adv_flow_dur > self.og_flow_dur:
                print("adv_flow_dur > og_flow_dur")
                directions = self.get_start_and_end_pkt_directon()
                # if directions[0] == "F" and directions[1] == "F":
                toextend = self.adv_flow_dur - self.og_flow_dur
                print(toextend)
                print(self.flow.pkts[self.flow.flowStats.flowLen - 1].ts)
                print(self.flow.pkts[self.flow.flowStats.flowLen - 1].ts + toextend)
                self.flow.pkts[self.flow.flowStats.flowLen - 1].ts += toextend
                print(self.flow.pkts[self.flow.flowStats.flowLen - 1].ts)

                if self.flow.pkts[self.flow.flowStats.flowLen - 1].ts - self.flow.pkts[self.flow.flowStats.flowLen - 2].ts > self.adv_fwd_iat_max:
                    print("max iAT time exceeded")
                    self.flow.calcPktIAStats()
                    print(self.flow.flowStats)
                    self.distribute_create_min_max_iat_inc(directions[1]) # for increasing flow duration
                    print(self.flow.pkts[self.flow.flowStats.flowLen - 1].ts)
                    print(self.flow.pkts[self.flow.flowStats.flowLen - 1].ts - self.flow.pkts[self.flow.flowStats.flowLen - 2].ts)
                else:
                    print("max IAT not exceeded, all good")
                    print("NEED TO CREATE MIN IAT!")

            elif self.adv_flow_dur < self.og_flow_dur:
                print("adv_flow_dur < og_flow_dur")
                toreduce = self.og_flow_dur - self.adv_flow_dur
                directions = self.get_start_and_end_pkt_directon()
                if directions[0] == "F" and directions[1] == "F":
                    print("flow_dur new 0: {}".format(self.flow.pkts[self.flow.flowStats.flowLen - 1].ts - self.flow.pkts[0].ts))
                    pkt_N_old_ts = self.flow.pkts[self.flow.flowStats.flowLen - 1].ts

                    self.flow.pkts[self.flow.flowStats.flowLen - 1].ts -= toreduce
                    print("flow_dur new 01: {}".format(self.flow.pkts[self.flow.flowStats.flowLen - 1].ts - self.flow.pkts[0].ts))

                    print("toreduce: {}".format(toreduce))
                    self.distribute_create_min_max_iat_dec(pkt_N_old_ts, directions[1])

                elif directions[0] == "F" and directions[1] == "B":
                    pkt_N_old_ts = self.flow.pkts[self.flow.flowStats.flowLen - 1].ts
                    biPkt_N_old_ts = self.flow.biPkts[len(self.flow.biPkts) - 1].ts
                    self.flow.biPkts[len(self.flow.biPkts) - 1].ts -= toreduce

                    prev_dur = (biPkt_N_old_ts - self.flow.pkts[0].ts)
                    cur_dur = (self.flow.biPkts[len(self.flow.biPkts) - 1].ts - self.flow.pkts[0].ts)

                    fraction_reduced = (prev_dur - cur_dur) / prev_dur
                    print("fraction reduced (F,B): {}".format(fraction_reduced))
                    self.distribute(fraction_reduced, False, directions[1])

                    self.distribute_create_min_max_iat_dec(pkt_N_old_ts, directions[1])




            # self.avgStdIATimes()
            # print("Done updating iatimes")
            self.updateBiTS()
            self.flow.getDiffs()
        else:
            self.avgStdIATimes()

        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        print("post iat trans stats: {}".format(self.flow.flowStats))

        if self.biFlowFlag:
            ts_bi_end = self.flow.biPkts[len(self.flow.biPkts) - 1].ts
            ts_end = self.flow.pkts[len(self.flow.pkts) - 1].ts
            ts_bi_start = self.flow.biPkts[0].ts
            ts_start = self.flow.pkts[0].ts
            if ts_bi_end > ts_end:
                end = ts_bi_end
            else:
                end = ts_end

            if ts_bi_start < ts_start:
                start = ts_start
            else:
                start = ts_start

            print("duration: {}".format(end - start))

    def distribute_create_min_max_iat_inc(self, last_pkt_dir):
        fraction_reduced = self.create_max()
        self.distribute(fraction_reduced, True, last_pkt_dir)
        self.create_min(fraction_reduced)

    def distribute_create_min_max_iat_dec(self, pkt_N_old_ts, last_pkt_dir):
        fraction_reduced = self.create_max_dec(pkt_N_old_ts)
        self.distribute(fraction_reduced, True, last_pkt_dir)
        self.flow.calcPktIAStats()
        print("new diffs: {}".format(self.flow.getDiffs()))
        self.create_min(fraction_reduced)

    def create_max_dec(self, pkt_N_old_ts):
        if self.flow.flowStats.flowLen == 2:
            print("already set flow duration, can't change min/max with flow of only 2 pkts")
            return
        num_flow_pkts = self.flow.flowStats.flowLen
        pkt_0 = self.flow.pkts[0]
        pkt_1 = self.flow.pkts[1]
        pkt_N = self.flow.pkts[num_flow_pkts - 1]  # this was pkt pushed in to match flow dur

        prev_diff = pkt_N_old_ts - pkt_1.ts

        toMaxIAT = self.adv_fwd_iat_max - (pkt_1.ts - pkt_0.ts)
        pkt_1.ts += toMaxIAT

        print("prev_diff: {}".format(prev_diff))

        if pkt_1.ts > pkt_N.ts:
            print("Error, max IAT exceeds flow duration.  Exiting...")
            exit(-1)

        cur_diff = pkt_N.ts - pkt_1.ts
        if cur_diff < 0:
            print("Error! pkt_1 is past pkt_N...should not happen.  Exiting...")
            exit(-1)

        print("cur_diff: {}".format(cur_diff))
        print("last pkt.ts: {}".format(self.flow.pkts[num_flow_pkts - 1].ts))
        fraction_reduced = (prev_diff - cur_diff) / prev_diff
        print("frac_reduced: {}".format(fraction_reduced))
        print("flow_dur new: {}".format(self.flow.pkts[num_flow_pkts - 1].ts - self.flow.pkts[0].ts))
        print("flow_dur new 2: {}".format(pkt_N.ts - self.flow.pkts[0].ts))

        return fraction_reduced
        # print(fraction_reduced)

    def create_max(self):
        if self.flow.flowStats.flowLen == 2:
            print("already set flow duration, can't change min/max with flow of only 2 pkts")
            return
        num_flow_pkts = self.flow.flowStats.flowLen
        pkt_0 = self.flow.pkts[0]
        pkt_1 = self.flow.pkts[1]
        pkt_N = self.flow.pkts[num_flow_pkts - 1] # this was pkt pushed out to match flow dur

        prev_diff = pkt_N.ts - pkt_1.ts

        toMaxIAT = self.adv_fwd_iat_max - (pkt_1.ts - pkt_0.ts)
        pkt_1.ts += toMaxIAT

        if pkt_1.ts > pkt_N.ts:
            print("Error, max IAT exceeds flow duration.  Exiting...")
            exit(-1)

        cur_diff = pkt_N.ts - pkt_1.ts
        if cur_diff < 0:
            print("Error! pkt_1 is past pkt_N...should not happen.  Exiting...")
            exit(-1)

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
        print(len(self.flow.diffs))
        print("total flow len: {}".format(self.flow.flowStats.flowLen))
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
                    k += 1
                    i += 1
                    if f_count == 2: # reached
                        max_created = False
                elif self.flow.diffs[k][0] == "B":
                    prev_ts = self.flow.biPkts[j].ts
                    j += 1
                    k += 1
            elif not max_created:
                # print(i,j,k,f_count, self.flow.diffs[k][0])
                if self.flow.diffs[k][0] == "F":
                    self.flow.pkts[i].ts = prev_ts + (1 - fraction_reduced) * self.flow.diffs[k][1]
                    prev_ts = self.flow.pkts[i].ts
                    k += 1
                    i += 1
                elif self.flow.diffs[k][0] == "B":
                    self.flow.biPkts[j].ts = prev_ts + (1 - fraction_reduced) * self.flow.diffs[k][1]
                    prev_ts = self.flow.biPkts[j].ts
                    k += 1
                    j += 1

        print(self.flow.diffs)
        self.flow.getDiffs()
        print(self.flow.diffs)

        # step = (self.flow.pkts[i].ts - self.flow.pkts[i - 1].ts) / num_flow_pkts

    def create_min(self, fraction_reduced):
        self.flow.calcPktIAStats()
        print("Create MIN")
        if self.flow.flowStats.flowLen <= 3:
            print("Error: Can't create min IAT since less than 3 pkts. Exiting...")
            exit(-1)
        if self.adv_fwd_iat_min < self.flow.flowStats.minIA:
            print("decrease minIA")
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
                print("No back to back pkts")
                if self.adv_fwd_iat_min == 0:
                    print("Min == 0, can't get down to that")
                    self.flow.pkts[2].ts = self.flow.pkts[1].ts + 0.0000001

        elif self.adv_fwd_iat_min > self.flow.flowStats.minIA:
            print("Increase minIA")
            flag = False
            prev_ts = self.flow.pkts[0]
            loops = 0
            while self.flow.flowStats.minIA < self.adv_fwd_iat_min and loops < MAX_PKT_IAT_LOOPS:
                for i in range(0, self.flow.flowStats.flowLen - 1):
                    # print("i: {}".format(i))
                    # print("dif: {}".format(self.flow.pkts[i + 1].ts - self.flow.pkts[i].ts))
                    if self.flow.pkts[i + 1].ts - self.flow.pkts[i].ts <= self.flow.flowStats.minIA:
                        print("fwd min iA: {}".format(self.flow.pkts[i + 1].ts - self.flow.pkts[i].ts))
                        toextend = self.adv_fwd_iat_min - self.flow.flowStats.minIA
                        # print("flow min iA: {}".format(self.flow.flowStats.minIA))
                        # print("adv_iat_min: {}".format(self.adv_fwd_iat_min))
                        # print("toextend: {}".format(toextend))
                        self.flow.pkts[i + 1].ts += toextend
                        print("fwd new min iA: {}".format(self.flow.pkts[i + 1].ts - self.flow.pkts[i].ts))
                        if i != self.flow.flowStats.flowLen - 3 and self.flow.pkts[i + 1].ts > self.flow.pkts[i + 2].ts:
                            print("bigger min IAT pushed past next pkt!")
                            k = i + 2
                            while k != self.flow.flowStats.flowLen - 1:
                                test = self.flow.pkts[k].ts + toextend
                                if test < self.flow.pkts[k + 1].ts and self.flow.pkts[k + 1].ts - test > self.adv_fwd_iat_min:
                                    self.flow.pkts[k].ts += toextend
                                    flag = True
                                    break
                                else:
                                    k += 1
                            if k == self.flow.flowStats.flowLen - 1:
                                print("can't make min IAT!")
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
                        print("min IAT created!")
                        break
                self.flow.calcPktIAStats()
                print("about to loop min iA: {}".format(self.flow.flowStats.minIA))
                loops += 1

            if loops == MAX_PKT_LOOPS:
                print("Max Pkt loops reached when created fwd min IAT!")




        #
        #     for i in range(1, self.flow.flowStats.flowLen):
        #
        #
        #     self.flow.pkt[2].ts = self.flow.pkt[1].ts + self.adv_fwd_iat_min
        #





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



    def avgStdIATimes(self):
        # X = get_truncnorm(self.adv_fwd_iat_mean * 1000, self.adv_fwd_iat_std * 1000, self.adv_fwd_iat_min, self.adv_fwd_iat_max)  #lower bound "min" in config, upper bound "max" if exists, else maxIA
        X = get_truncnorm(.04, 1, 0, 2)

        X = X.rvs(self.flow.flowStats.flowLen - 1)  # -1 since already have t0 in place

        print(X)

        # Best effort reconstruction
        prev = self.flow.pkts[0].ts
        for i in range(1, self.flow.flowStats.flowLen):
            # print(X[i-1])
            self.flow.pkts[i].ts = prev + X[i-1]
            prev = self.flow.pkts[i].ts
            i += 1

        # print("pkts 0,1: {}, {}".format(self.flow.pkts[0].ts, self.flow.pkts[1].ts))

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
                        print("F didn't move to other side of B, so think we're good???")
                # print("len bis[]: {}".format(len(bis)))

            elif self.flow.diffs[k][0] == "F":
                prev_ts = self.flow.pkts[i].ts
                i += 1
                k += 1
                if i >= len(self.flow.pkts):
                    lastFDiffIndex = k
            else:
                prev_ts = self.flow.pkts[i].ts
                print("F AND B AT SAME TIME!")
                i += 1
                j += 1
                k += 1




class FlagTransform(Transform):
    def __init__(self, flowObj, config, logger):
        Transform.__init__(self, flowObj, config, logger)
        self.logger.info("Creating new FlagTransform Object")

    def Process(self):
        self.flow.calcPktLenStats()
        self.flow.calcPktIAStats()
        self.logger.info("FlagTransform Process()")



####################################################
####################################################
####################################################
####################################################
#
#
# class TransPktLens(Transform):
#     def __init__(self, flowObj, config):
#         Transform.__init__(self, flowObj, config)
#         # print("Creating new TransPktLens Object")
#
#     def Process(self):
#         self.flow.calcPktLenStats()
#         self.flow.calcPktIAStats()
#         if self.flow.flowStats.flowLenBytes == 0:
#             print("all ptks have payload == 0.  returning...")
#             return
#         print("# of pkts in flow: {}".format(self.flow.flowStats.flowLen))
#         # print("Transforming pkt lengths on these pkts: {}".format(self.flow))
#         # print("pre len trans: {}".format(self.flow.flowStats))
#
#         #print(self.config)
#         #print(self.flow.flowStats)
#         #self.testPktSplit()
#
#         # TODO: uncomment!  This does the pkt length manipulation
#         if self.flow.flowStats.avgLen < self.config["pktLens"]["avg"]:
#             self.mergeLooper()
#         elif self.flow.flowStats.avgLen > self.config["pktLens"]["avg"]:
#             self.splitLooper()
#
#         print("post len trans: {}".format(self.flow.flowStats))
#
#     def mergeLooper(self):
#         i = totalLoops = 0
#         MaxPktLen = self.config["pktLens"]["max"]
#         # MERGE PACKETS
#         while self.flow.flowStats.avgLen < self.config["pktLens"]["avg"]:
#             if i + 1 == self.flow.flowStats.flowLen:
#                 if totalLoops == MAX_PKT_LOOPS:
#                     print("Reached max pkt loops, can't merge more pkts.  avg still < target avg")
#                     # print("i: {}".format(i))
#                     break
#                 i = 0
#                 totalLoops += 1
#                 continue
#             # print("flags: {}".format(self.flow.pkts[i].get_flags()))
#             if self.flow.pkts[i].pload_len and self.flow.pkts[i + 1].pload_len:
#                 if self.flow.pkts[i].pload_len + self.flow.pkts[i + 1].pload_len >= MaxPktLen:
#                     i += 1
#                 elif self.mergePkt(self.flow.pkts[i], self.flow.pkts[i + 1]):
#                     self.flow.calcPktLenStats()
#                 else:
#                     i += 1
#             else:
#                 i += 1
#
#
#     def splitLooper(self):
#         avgPktLen = self.config["pktLens"]["avg"]
#         try:
#             maxPktLen = self.config["pktLens"]["max"]
#         except KeyError:
#             maxPktLen = 1418
#         try:
#             minPktLen = self.config["pktLens"]["min"]
#         except KeyError:
#             minPktLen = 0
#
#         i = totalLoops = 0
#         # SPLIT PACKETS, start with packets > maxPktLen set by user
#         while self.flow.flowStats.avgLen > avgPktLen and self.flow.flowStats.maxLen > maxPktLen:
#             if i == self.flow.flowStats.flowLen:
#                 if totalLoops == MAX_PKT_LOOPS:
#                     # print("Reached max pkt loops, can't split more pkts.  max pkt len too small")
#                     break
#                 i = 0
#                 totalLoops += 1
#                 continue
#             if self.flow.pkts[i].pload_len > 0 and self.flow.pkts[i].pload_len > maxPktLen:
#                 if self.flow.pkts[i].pload_len // 2 < minPktLen:        # don't split packet if goes below min pkt len
#                     i += 1
#                     continue
#                 self.splitPkt(self.flow.pkts[i], i)
#                 self.flow.calcPktLenStats()
#                 i += 2
#             else:
#                 i += 1
#
#         # if still haven't reached avg len.  Begin splitting all other packets with payload
#         pktsLessThanMinPktLen = 0
#         minPktFlag = False
#         if minPktLen > 0:
#             minPktFlag = True
#         i = totalLoops = 0
#         while self.flow.flowStats.avgLen > avgPktLen: # case where max pktLen < config max pktLen but avg pktLen is still too large
#             if minPktLen and self.flow.flowStats.flowLen <= pktsLessThanMinPktLen:
#                 warnings.warn("Min Packet Length set by user too small!")
#                 warnings.warn("Can't converge on avg. packet length.  Ignorning min pkt length requirement")
#                 minPktFlag = False
#             if i == self.flow.flowStats.flowLen:
#                 if totalLoops == MAX_PKT_LOOPS:
#                     warnings.warn("Reached max pkt loops, can't split more pkts.  avg still > target avg.  NOT CONVERGED")
#                     break
#                 i = 0
#                 totalLoops += 1
#                 pktsLessThanMinPktLen = 0
#                 continue
#             if minPktFlag and self.flow.pkts[i].pload_len // 2 < minPktLen:  # don't split packet if goes below min pkt len
#                 i += 1
#                 pktsLessThanMinPktLen += 1
#                 continue
#             if self.flow.pkts[i].pload_len > 0:
#                 self.splitPkt(self.flow.pkts[i], i)
#                 self.flow.calcPktLenStats()
#                 i += 2
#             else:
#                 i += 1
#
#         # NOT GOING TO SPLIT ACKS. uncomment if want to split acks
#         # # after trying to split payloads, we're now going to allow the splitting acks (last resort)
#         # i = totalLoops = 0
#         # while self.flow.flowStats.avgLen > avgPktLen:  # case where max pktLen < config max pktLen but avg pktLen is still too large
#         #     if i == self.flow.flowStats.flowLen:
#         #         if totalLoops == MAX_PKT_LOOPS:
#         #             print("Reached max pkt loops, can't split more pkts.  avg still > target avg.  NOT CONVERGED")
#         #             # print("i: {}".format(i))
#         #             break
#         #         i = 0
#         #         totalLoops += 1
#         #         continue
#         #     self.splitPkt(self.flow.pkts[i], i)
#         #     self.flow.calcPktLenStats()
#         #     i += 2
#
#     def mergePkt(self, pkt, npkt):
#         if pkt.http_pload and npkt.http_pload:# and (pkt.tcp_flags == npkt.tcp_flags): # make sure both pkts have payload and same flags
#             # print("prePKT: {}".format(pkt))
#             # print("preNPKT: {}".format(npkt))
#
#             pkt.http_pload += npkt.http_pload
#             pkt.ip_len = pkt.ip_len + len(npkt.http_pload)
#
#             # print("postPKT: {}".format(pkt))
#             # print("postNPKT: {}".format(npkt))
#
#             self.flow.pkts.remove(npkt)
#             return True
#             # self.pktsToRemove.append(npkt)
#         else:
#             # print("CAN'T MERGE PACKETS")
#             return False
#
#     def splitPkt(self, pkt, index):
#         dupPkt = copy.deepcopy(pkt)
#         oldPktLen = pkt.frame_len
#
#         if pkt.http_pload:
#             self.splitPayload(pkt, dupPkt)
#             #print("split payload")
#         else:
#             self.fixACKnum(pkt, dupPkt)
#             #print("split ack")
#
#         # update IP ID
#         dupPkt.ip_id += 1  # TODO: increment ipID (this will need to be adjusted at end of flow processing)
#         self.flow.pkts.insert(index + 1, dupPkt)
#         #self.flow.addPkt(dupPkt)
#         # self.flow.incSplitLenStats(oldPktLen, pkt.frame_len, dupPkt.frame_len)
#
#         #return dupPkt
#
#     def splitPayload(self, pkt, dupPkt):
#         len_payload = len(pkt.http_pload)
#         ip_hdr_len = pkt.ip_len - len_payload
#         dupPkt.http_pload = pkt.http_pload[len_payload // 2:]
#         pkt.http_pload = pkt.http_pload[:len_payload // 2]
#
#         pkt.ip_len = ip_hdr_len + len(pkt.http_pload)
#         dupPkt.ip_len = ip_hdr_len + len(dupPkt.http_pload)
#
#         dupPkt.seq_num += len(pkt.http_pload)
#
#     def fixACKnum(self, pkt, dupPkt):
#         biPkt = self.getMostRecentBiPkt(dupPkt)
#         if biPkt:
#             if not biPkt.http_pload:
#                 print("ERROR: ACKing an ACK.  uh oh!  biPkt should have a payload!")
#                 exit(-1)
#             pkt.ackSplitCount += 1
#             dupPkt.ackSplitCount += 1
#             pkt.ack_num -= len(biPkt.http_pload) // pkt.ackSplitCount + 1 # add plus one to avoid duplicate ack
#
#     # Find the closest biPkt to dupPkt that has payload w/o storing a bunch of pkts
#     # TODO (low): optimize to do O(log n) search since biPkt list is sorted
#     def getMostRecentBiPkt(self, pkt):
#         flag = False
#         biPkt = self.flow.biPkts[len(self.flow.biPkts)-1]
#         for biPktObj in reversed(self.flow.biPkts):
#             if biPktObj.ts < pkt.ts and biPktObj.http_pload:
#                 flag = True
#                 biPkt = biPktObj
#                 break
#         if flag:
#             return biPkt
#         else:
#             return flag
#
#     def testPktSplit(self):
#         print(self.flow.flowStats)
#         newPkts = []
#         for p in self.flow.pkts:
#             newPkts.append(self.splitPkt(p))
#         self.flow.pkts += newPkts
#         self.flow.pkts.sort()
#         # self.splitPkt(self.flow.pkts[17])
#         # print("Transforming Pkt Lengths on these pkts: {}".format(self.flow))
#
# class TransIATimes(Transform):
#     def __init__(self, flowObj, config, biFlowFlag):
#         Transform.__init__(self, flowObj, config)
#         self.biFlowFlag = biFlowFlag
#         print("Creating new TransIATimes Object")
#
#     def Process(self):
#         # self.flow.calcPktLenStats()
#         # self.flow.calcPktIAStats()
#         #TODO: make sure lenStats are updated before this section!
#         print("Transforming IA Times on these pkts: {}".format(self.flow))
#
#         # check if there are pkts going in opposite direction
#         if self.biFlowFlag:
#             self.flow.getDiffs()
#             # print("\nDone getting diffs")
#             self.avgStdIATimes()
#             # print("Done updating iatimes")
#             self.updateBiTS()
#             self.flow.getDiffs()                    # once it works I think you can delete this
#         else:
#             self.avgStdIATimes()
#
#         # self.flow.calcPktLenStats()
#         self.flow.calcPktIAStats()
#         #print(self.flow.flowStats)
#         #self.updateBiTS()
#
#     def avgStdIATimes(self):
#         targ_avg = self.config["iaTimes"]["avg"]
#         targ_std = self.config["iaTimes"]["stddev"]
#         if "max" in self.config["iaTimes"]:
#             targ_max = self.config["iaTimes"]["max"]
#         else:
#             targ_max = self.flow.flowStats.maxIA
#
#         # if "min" in self.config["iaTimes"]:
#         #     targ_min = self.config["iaTimes"]["min"]
#         # else:
#         #     targ_min = 0
#
#         targ_min = 0
#
#         X = get_truncnorm(targ_avg, targ_std, targ_min, targ_max)  #lower bound "min" in config, upper bound "max" if exists, else maxIA
#         X = X.rvs(self.flow.flowStats.flowLen - 1)  # -1 since already have t0 in place
#
#         # Best effort reconstruction
#         prev = self.flow.pkts[0].ts
#         for i in range(1, self.flow.flowStats.flowLen):
#             # print(X[i-1])
#             self.flow.pkts[i].ts = prev + X[i-1]
#             prev = self.flow.pkts[i].ts
#             i += 1
#
#         # print("pkts 0,1: {}, {}".format(self.flow.pkts[0].ts, self.flow.pkts[1].ts))
#
#     def updateBiTS(self):
#         i = j = k = 0
#         prev_ts = None
#         prev_dir = self.flow.diffs[0][0]                # TODO: make diff list a list of namedtuples!
#         if prev_dir == "F":
#             prev_ts = self.flow.pkts[0].ts
#             i += 1
#         elif prev_dir == "B":
#             prev_ts = self.flow.biPkts[0].ts
#             j += 1
#         elif prev_dir == "S":
#             print("ERROR? FLOW STARTS AT SAME TIME?!?!?! in updateBiTS()")
#             print("Exiting...")
#             exit(-1)
#             # i += 1
#             # j += 1
#         else:
#             print("ERROR! updateBiTS() error!")
#             exit(-1)
#         k += 1
#
#         # print("i: {}, j: {}, k: {}".format(i,j,k))
#
#         lastFDiffIndex = None
#
#         while k < len(self.flow.diffs):
#         #for dir in range(1,len(self.flow.diffs)):
#             # print("k: {}".format(k))
#             # print("sup")
#             # print(self.flow.diffs)
#             # print(self.flow.diffs[k][0])
#             # print("ts diff: {}".format(self.flow.pkts[1].ts - self.flow.pkts[0].ts))
#             if self.flow.diffs[k][0] == "B":
#                 count = 0
#                 bis = []
#                 while k < len(self.flow.diffs) and self.flow.diffs[k][0] == "B":
#                     # print("k: {}".format(k))
#                     # print(self.flow.)
#                     # print("b looping")
#                     count += 1
#                     bis.append(j)
#                     j += 1
#                     k += 1
#                 # print(count)
#                 # if count == 0:
#                 #     count == 1
#                 # print(bis)
#                 # print("i: {}".format(i))
#                 # print("pkts: {}".format(self.flow.pkts))
#                 # TODO: if B is last pkt, then no step needed.  take all b packets and add
#                 if k != len(self.flow.diffs):   # at least one more F in biflow
#                     step = (self.flow.pkts[i].ts - self.flow.pkts[i-1].ts) / count
#                     # print("step: {}".format(step))
#                     #print(count)
#                     m = 0
#                     for n in bis:
#                         #print("n: {}".format(n))
#                         self.flow.biPkts[n].ts = self.flow.pkts[i-1].ts + step * m + step / 2
#                         m += 1
#                 else: # signifies B is last pkt
#                     if self.flow.pkts[i - 1].ts > self.flow.biPkts[bis[0]].ts:      # F pkt moved ahead of B after IAT trans
#                         # TODO: move all bipkts whose index is in bis[] on other side of last F
#                         # B0.ts = last_F.ts + (B0 - last_F.ts)
#                         # B0.ts - last_F.ts is stored in diffs at
#                         # print("need to move B pkts on other side of the last F")
#                         p_ts = self.flow.pkts[i - 1].ts
#                         for n in bis:
#                             # print("lastfDiffIndex: {}".format(lastFDiffIndex))
#                             self.flow.biPkts[n].ts = p_ts + self.flow.diffs[lastFDiffIndex][1]
#                             p_ts = self.flow.biPkts[n].ts
#                             lastFDiffIndex += 1
#                     else:
#                         print("F didn't move to other side of B, so think we're good???")
#                 # print("len bis[]: {}".format(len(bis)))
#
#             elif self.flow.diffs[k][0] == "F":
#                 prev_ts = self.flow.pkts[i].ts
#                 i += 1
#                 k += 1
#                 if i >= len(self.flow.pkts):
#                     lastFDiffIndex = k
#             else:
#                 prev_ts = self.flow.pkts[i].ts
#                 print("F AND B AT SAME TIME!")
#                 i += 1
#                 j += 1
#                 k += 1

class TransDistUDP(Transform):
    def __init__(self, flowObj, config):
        Transform.__init__(self, flowObj, config)
        # print("Creating new TransSplitPkts Object")

    def Process(self):
        print("Process TransDistUDP")
        self.flow.calcPktLenStats()
        self.split_flow()

    def split_flow(self):
        numFlows = self.config["numFlows"]
        # print(self.flow.flowStats.flowLen)
        pktsPerSplitFlow = ceil(self.flow.flowStats.flowLen / numFlows)
        flowKeys = []
        flowKeys.append(self.flow.flowKey)
        # print(flowKeys)
        self.genNewFlowKeys(numFlows, flowKeys)
        # print(flowKeys)
        self.updatePktFlowKeys(flowKeys, pktsPerSplitFlow)

    def genNewFlowKeys(self, numFlows, flowKeys):
        newIPs = []
        newPorts = []
        proto = self.flow.flowKey[0]
        IPsrc = self.flow.flowKey[1]
        portSrc = self.flow.flowKey[2]
        IPdst = self.flow.flowKey[3]

        IPsrc_split = IPsrc.split(".", 3)
        IPsrcSubnet0 = IPsrc_split[0]
        IPsrcSubnet8 = IPsrc_split[1]
        IPsrcSubnet16 = IPsrc_split[2]
        IPsrcSubnet24 = IPsrc_split[3]

        for i in range(numFlows - 1):
            flag = True
            while flag:
                IP24_prime = randint(0, 255)
                if IP24_prime != int(IPsrcSubnet24) and IP24_prime not in newIPs:
                    flag = False
                    newIPs.append(IP24_prime)
                    #print(IP24_prime)
                IPsrc_prime = IPsrcSubnet0 + "." + IPsrcSubnet8 + "." + IPsrcSubnet16 + "." + str(IP24_prime)
                #print(IPsrc_prime)
            flag = True
            while flag:
                portSrc_prime = randint(0, 65535)
                if portSrc_prime != int(portSrc) and portSrc_prime not in newPorts:
                    flag = False
                    newPorts.append(portSrc_prime)
                    #print(portSrc_prime)
            flowKey_prime = (proto, IPsrc_prime, portSrc_prime, IPdst)
            #print(self.flow.flowKey)
            #print(flowKey_prime)
            flowKeys.append(flowKey_prime)
        return flowKeys

    def updatePktFlowKeys(self, flowKeys, pktsPerSplitFlow):
        current = pktCounter = 0
        indexCounter = 0
        # print("total pkts in flow: {}".format(len(self.flow.pkts)))
        for pkt in self.flow.pkts:
            pkt.pktSetUDPTuple(flowKeys[current])
            pktCounter += 1
            if pktCounter == pktsPerSplitFlow or pkt == self.flow.pkts[len(self.flow.pkts)-1]:
                pktCounter = 0
                current += 1
            indexCounter += 1



# class TransSplitPkts(Transform):
#     def __init__(self, flowObj, config):
#         Transform.__init__(self, flowObj, config)
#         print("Creating new TransSplitPkts Object")
#
#     def Process(self):
#         print("Process TransSplitPkts")
#         self.flow.calcPktLenStats()
#         self.flow.calcPktIAStats()
#         self.splitFlow()
#
#     def splitFlow(self):
#         numFlows = self.config["numFlows"]
#         pktsPerSplitFlow = ceil(self.flow.flowStats.flowLen / numFlows) #TODO: the floor() may cause rounding issues and result in lost pkts...
#         print("pkts per splitflow: {}".format(pktsPerSplitFlow))
#         flowKeys = []
#         timestamps = []
#         startPkts = []          # this holds indices of first pkt in each new splitFlow
#         flowKeys.append(self.flow.flowKey)
#         self.genNewFlowKeys(numFlows, flowKeys)
#         print("New Flow Keys: {}".format(flowKeys))
#
#         print(self.flow.pkts)
#         self.updatePktFlowKeys(flowKeys, pktsPerSplitFlow, timestamps, startPkts)
#         print(self.flow.pkts)
#         print(timestamps)
#
#         print(self.flow.biPkts)
#         self.updateBiPktFlowKeys(flowKeys, timestamps)
#         print(self.flow.biPkts)
#
#         print("start pkts: {}".format(startPkts))
#         print(flowKeys)
#
#         if self.flow.flowKey[0] == 6: # TODO: will also need to check if the attack requires this (slowloris does not, patator does)
#             print("TCP")
#             for i in range(numFlows-1):
#                 # Check cases where we split in the middle of a tcp 3way HS
#                 sFlag = saFlag = aFlag = True
#                 firstPkt = self.flow.pkts[startPkts[i]]
#                 if firstPkt.tcp_flags == "S":   # don't create 3wHS since already exists
#                     sFlag = saFlag = aFlag = False
#                 elif firstPkt.tcp_flags == "SA": # We just need to create a SYN flag to match the SA
#                     saFlag = aFlag = False
#                 elif startPkts[i]-1 != 0 and firstPkt.tcp_flags == "A" and self.flow.pkts[startPkts[i] - 1].tcp_flags == "SA":   # ack is from end of 2wHS
#                     aFlag = False # don't need to create ACK
#
#                 newSyn = newSynAck = None
#                 print("index to insert: {}".format(startPkts[i]))
#                 if sFlag:
#                     newSyn = self.createSYNPkt(firstPkt)
#                     self.flow.pkts.insert(startPkts[i], newSyn) # TODO: these are being inserted in the wrong spot
#                 # if saFlag:
#                 #     if newSyn == None:
#                 #         print("ERROR.  SA created without an S!  Bad!")
#                 #     newSynAck = self.createSYNACKPkt(firstPkt, newSyn)
#                 #     self.flow.pkts.insert(startPkts[i] - 1, newSynAck)
#                 # if aFlag:
#                 #     print("Creating ACK for 3wHS")
#
#         # TODO:
#         # 1) insert 3 way HS
#         # 2) insert fin-fin/ack
#         # 3) Delete original flow from table, load splitflows into flow table
#
#
#
#     def genNewFlowKeys(self, numFlows, flowKeys):
#         newIPs = []
#         newPorts = []
#         proto = self.flow.flowKey[0]
#         IPsrc = self.flow.flowKey[1]
#         portSrc = self.flow.flowKey[2]
#         IPdst = self.flow.flowKey[3]
#         portDst = self.flow.flowKey[4]
#
#         IPsrc_split = IPsrc.split(".", 3)
#         IPsrcSubnet0 = IPsrc_split[0]
#         IPsrcSubnet8 = IPsrc_split[1]
#         IPsrcSubnet16 = IPsrc_split[2]
#         IPsrcSubnet24 = IPsrc_split[3]
#
#         for i in range(numFlows - 1):
#             flag = True
#             while flag:
#                 IP24_prime = randint(0, 255)
#                 if IP24_prime != int(IPsrcSubnet24) and IP24_prime not in newIPs:
#                     flag = False
#                     newIPs.append(IP24_prime)
#                     #print(IP24_prime)
#                 IPsrc_prime = IPsrcSubnet0 + "." + IPsrcSubnet8 + "." + IPsrcSubnet16 + "." + str(IP24_prime)
#                 #print(IPsrc_prime)
#             flag = True
#             while flag:
#                 portSrc_prime = randint(0, 65535)
#                 if portSrc_prime != int(portSrc) and portSrc_prime not in newPorts:
#                     flag = False
#                     newPorts.append(portSrc_prime)
#                     #print(portSrc_prime)
#             flowKey_prime = (proto, IPsrc_prime, portSrc_prime, IPdst, portDst)
#             #print(self.flow.flowKey)
#             #print(flowKey_prime)
#             flowKeys.append(flowKey_prime)
#         return flowKeys
#
#     def updatePktFlowKeys(self, flowKeys, pktsPerSplitFlow, timestamps, startPkts):
#         ts0 = self.flow.pkts[0].ts
#         current = pktCounter = 0
#         indexCounter = 0
#         print("total pkts in flow: {}".format(len(self.flow.pkts)))
#         for pkt in self.flow.pkts:
#             # print(pkt.ts)
#
#             #pkt.flow_tuple = flowKeys[current]
#             pkt.pktSet5Tuple(flowKeys[current])
#             pktCounter += 1
#             #print(pktCounter)
#             if pktCounter == pktsPerSplitFlow or pkt == self.flow.pkts[len(self.flow.pkts)-1]:
#                 ts1 = pkt.ts
#                 pktCounter = 0
#                 timestamps.append((ts0, ts1))
#                 ts0 = ts1
#                 current += 1
#                 #print("#############################")
#                 if pkt != self.flow.pkts[len(self.flow.pkts) - 1]:
#                     startPkts.append(indexCounter + 1)
#             indexCounter += 1
#
#     def updateBiPktFlowKeys(self, flowKeys, timestamps):
#         splitFlowCounter = pktCounter = base = 0
#         for ts in timestamps:
#             for i in range(len(self.flow.biPkts) - 1):
#                 if base + pktCounter == len(self.flow.biPkts):
#                     break
#                 if self.flow.biPkts[base + pktCounter].ts > ts[0] and self.flow.biPkts[base + pktCounter].ts <= ts[1]:
#                     self.flow.biPkts[base + pktCounter].pktSet5Tuple((self.flow.biPkts[base + pktCounter].flow_tuple[0], self.flow.biPkts[base + pktCounter].flow_tuple[1], self.flow.biPkts[base + pktCounter].flow_tuple[2], flowKeys[splitFlowCounter][1], flowKeys[splitFlowCounter][2]))
#                 elif self.flow.biPkts[base + pktCounter].ts < ts[0]:
#                     pktCounter += 1
#                     continue
#                 else:
#                     # case where biPkts.ts > timestamps[1]
#                     base = base + pktCounter
#                     pktCounter = 0
#                     splitFlowCounter += 1
#                     break
#                 pktCounter += 1
#
#
#     def genTCPHandshake(self):
#         print("generating TCP Handshake")
#
#     def genFinConnection(self):
#         print("generating FIN -> Fin/ACK close connection")
#
#     def createSYNPkt(self, firstPkt):
#         print("createSYNPkt")
#         newPkt = copy.deepcopy(firstPkt)
#         length = None
#         if newPkt.http_pload:
#             length = len(newPkt.http_pload)
#             newPkt.seq_num = firstPkt.seq_num - length
#             newPkt.remove_payload()
#         else: # S, ACK, SA
#             print("NO PAYLOAD for createSYNPkt()")
#
#         #print(newPkt.printSummary())
#         newPkt.set_flags("S")
#         newPkt.ack_num = 0
#         newPkt.addSYNOptions()
#         #print(newPkt.printSummary())
#         newPkt.frame_len = newPkt.len()
#         newPkt.ip_len = newPkt.frame_len
#         #print(newPkt.len())
#
#         f_ts = firstPkt.ts
#         mid = f_ts - 0.01
#         min = mid - 0.005
#         max = mid + 0.005
#
#         newPkt.ts = random.uniform(min, max)
#         #print(newPkt.printShow())
#         #print(firstPkt)
#         return newPkt
#
#     def createSYNACKPkt(self, firstPkt, synPkt):
#         print("create syn ack")
#         print("FIRST_PKT ACK_NUM: {}".format(firstPkt.ack_num))
#
#         print(firstPkt.printShow())
#         saPkt = copy.deepcopy(synPkt)
#         if firstPkt.ack_num != 0:
#             saPkt.seq_num = firstPkt.ack_num - 1            # TODO: this is wrong.  I'm getting -1
#         else:
#             saPkt.seq_num = 0
#         saPkt.ack_num = synPkt.seq_num + 1
#         saPkt.set_flags("SA")
#
#         saPkt.addSYNACKOptions()
#
#         #print(saPkt.printShow())
#
#         saPkt.frame_len -= 4
#         saPkt.ip_len = saPkt.frame_len
#
#         sTS = synPkt.ts
#         fTS = firstPkt.ts
#         ts = (fTS - sTS) / 2
#         mid = sTS + ts
#         quarter = (mid - ts) / 2
#         min = sTS + quarter
#         max = mid + quarter
#         saPkt.ts = random.uniform(min, max)
#         print(saPkt.printShow())
#
#         return saPkt
#
#         #saPkt.frame_len = saPkt.len()
#         # saPkt.ip_len = saPkt.frame_len
#         #
#         #
#         # print(saPkt.ip_len)
#
#




















