import json

class Config:
    def __init__(self, config_file):       # this needs to read in the actual config file and parse it
        if config_file:
            self.flows = {}
            self.total_flows_to_modify = 0
            with open(config_file) as f:
                self.data = json.load(f)
            self.parseConfig(self.data)
        else:
            print("ERROR: No configuration file")
            exit(-1)
        features_to_change = ["Tot Fwd Pkts",
                              "Fwd Pkt Len Max",
                              "Fwd Pkt Len Min",
                              "Pkt Len Min",
                              "Pkt Len Max",

                              "Flow Duration",
                              "Flow IAT Max",
                              "Flow IAT Min",
                              "Fwd IAT Max",
                              "Fwd IAT Min",

                              "Fwd PSH Flags",
                              "URG Flag Cnt",
                              "FIN Flag Cnt",
                              "CWE Flag Count",

                              "Init Fwd Win Byts"
                              ]

    def parseConfig(self, jData):
        # print("Parsing config and setting config vals...")
        # self.time_since_last_pkt = jData["sysConfig"]["timeout"]

        # convert JSON to python dictionary
        # for k,v in jData["flowFeatures"].items():
        for k,v in jData["flows"].items():
            for timeout,feature in v.items():
                key = [x.strip() for x in k.split(',')]
                # print(key)
                key[0] = int(key[0])
                key[2] = int(key[2])
                key[4] = int(key[4])
                # print(timeout, feature)
                key = tuple(key)
                key = (key, timeout)
                print("key: {}".format(key))
                # if key[0] == 17 and len(key) == 5: # need check in case dstPort was left off in config file already
                #     key.pop(4) # get rid of dstPort
                # key = tuple(key)
                self.total_flows_to_modify += 1
                if key[0][0] == 6:
                    self.flows[key] = v[timeout]
                elif key[0][0] == 17:
                    self.flows[key[:-1]] = v[timeout]
                else:
                    print("unknown protocol: {}".format(key[0]))
                #     print("Error: unexpected proto #...exiting...")
                #     exit(-1)
                    # print(key)

        #print(self.flows[(6, '155.98.38.79', 80, '142.44.154.169', 38130)]["pktLens"])