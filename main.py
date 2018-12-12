import sys
from scapy.all import *
from TransPkt import TransPkt
from TestTransPkt import TestTransPkt
from NetSploit import NetSploit
from Config import Config
from TestNetSploit import TestNetSploit


def check_input():
    if len(sys.argv) != 3:
        print("Error: Need to specify input pcap to edit and output pcap filename")
        print("e.g. python edit.py <input.pcap> <output.pcap>")
        exit()

    return sys.argv[1], sys.argv[2]



def main(iname, oname):
    pkts = rdpcap(iname)

    # This needs to be read from a config file (some config object?)
    #flow_filter_config = ["5Tuple_0", "5Tuple_1", "5Tuple_2", (6, '155.98.38.79', 80, '142.44.154.169', 38130)]
    #flow_filter = FlowFilter(flow_filter_config)       #define filter to check for 5 tuples

    config = Config("config_file.txt")      # TODO: this is not actually a file yet
    NS = NetSploit(config)


    for pkt in pkts:
        tpkt = TransPkt(pkt)

        NS.Process(tpkt)

        # tpkt.ts = 5
        # print(tpkt.ts)
        #
        # print(tpkt.eth_src)
        # tpkt.eth_src = "00:00:00:00:00:00"
        # print(tpkt.eth_src)
        #
        # tpkt.src_port = 23
        # tpkt.dst_port = 42
        # tpkt.seq_num = 1233
        #
        # #tpkt.write_pcap(oname)
        #
        # print(tpkt.flow_tuple)
        #
        # tpkt.ip_proto = 4
        # print(tpkt.flow_tuple)
        #
        # tpkt.set_URG()
        # tpkt.set_FIN()
        # tpkt.set_SYN()
        # tpkt.set_PSH()
        # print(tpkt.tcp_flags)
        # #tpkt.unset_FIN()
        # tpkt.unset_SYN()
        # print(tpkt.tcp_flags)
        # print(tpkt.ip_flags)
        # tpkt.unset_DF()
        # print(tpkt.ip_flags)

        Test = TestTransPkt(tpkt, pkt)
        Test.run_test()

    print(NS.pktMerger.inQueue)
    TestNetSploit(merger=NS.pktMerger)



if __name__ == "__main__":
    iname, oname = check_input()
    main(iname, oname)
