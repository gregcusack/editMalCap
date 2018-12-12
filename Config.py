

class Config:
    def __init__(self, config_file):       # this needs to read in the actual config file and parse it
        self.PktThresh = 10
        self.merge_batch_size = 20

        self.file_name = config_file        # just a place holder for now

        self.flow_filter_config = [
            "5Tuple_0",
            "5Tuple_1",
            "5Tuple_2",
            (6, '155.98.38.79', 80, '142.44.154.169', 38130),
            (6, '155.98.38.150', 80, '87.118.116.12', 36865)
        ]
