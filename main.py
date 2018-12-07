import sys
from scapy.all import *
from TransPkt import TransPkt
from TestTransPkt import TestTransPkt

def check_input():
    if len(sys.argv) != 3:
        print("Error: Need to specify input pcap to edit and output pcap filename")
        print("e.g. python edit.py <input.pcap> <output.pcap>")
        exit()

    return sys.argv[1], sys.argv[2]



def main(iname, oname):
    pkts = rdpcap(iname)
    for pkt in pkts:
        tpkt = TransPkt(pkt)

        Test = TestTransPkt(tpkt, pkt)
        Test.run_test()

        tpkt.ts = 5
        print(tpkt.ts)

        print(tpkt.eth_src)
        tpkt.eth_src = "00:00:00:00:00:00"
        print(tpkt.eth_src)

        tpkt.src_port = 23
        tpkt.dst_port = 42
        tpkt.seq_num = 1233

        #tpkt.write_pcap(oname)

        print(tpkt.flow_tuple)

        tpkt.ip_proto = 4
        print(tpkt.flow_tuple)

        tpkt.set_URG()
        tpkt.set_FIN()
        tpkt.set_SYN()
        tpkt.set_PSH()
        print(tpkt.tcp_flags)
        #tpkt.unset_FIN()
        tpkt.unset_SYN()
        print(tpkt.tcp_flags)
        print(tpkt.ip_flags)
        tpkt.unset_DF()
        print(tpkt.ip_flags)




if __name__ == "__main__":
    iname, oname = check_input()
    main(iname, oname)
