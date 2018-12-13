import json

class Config:
    def __init__(self, config_file):       # this needs to read in the actual config file and parse it
        if config_file:
            self.flows = {}
            with open(config_file) as f:
                self.data = json.load(f)
            self.parseConfig(self.data)
        else:
            print("ERROR: No configuration file")
            exit(-1)

    def parseConfig(self, jData):
        print("Parsing config and setting config vals...")
        self.pkt_thresh = jData["sysConfig"]["pkt_thresh"]
        self.time_since_last_pkt = jData["sysConfig"]["timeout"]
        self.merge_batch_size = jData["sysConfig"]["merge_batch_size"]

        # convert JSON to python dictionary
        for k,v in jData["flowFeatures"].items():
            key = [x.strip() for x in k.split(',')]
            key[0] = int(key[0])
            key[2] = int(key[2])
            key[4] = int(key[4])
            key = tuple(key)
            self.flows[key] = v

        print(self.flows[(6, '155.98.38.79', 80, '142.44.154.169', 38130)]["pktLens"])