from scapy.all import *
from TransformClasses.TransPkt import TransPkt
from TestClasses.TestTransPkt import TestTransPkt
from NetSploit import NetSploit
from Config import Config
from TestClasses.TestNetSploit import TestNetSploit
from pathlib import Path
from os import remove

def check_input():
    if len(sys.argv) != 3:
        print("Error: Need to specify input pcap to edit and output pcap filename")
        print("e.g. python edit.py <input.pcap> <output.pcap>")
        exit()

    return sys.argv[1], sys.argv[2]



def main(iname, oname):
    pkts = rdpcap(iname)

    config = Config("config.json")
    NS = NetSploit(config)

    counter = 0
    droppedPkts = 0
    for pkt in pkts:

        # print(pkt[IP].src)
        tpkt = TransPkt(pkt)
        if not tpkt.dropPkt:
            counter += 1
            NS.loadFlowTable(tpkt)
            # print(tpkt.ip_src)
        else: # TODO: need to write non-tcp/udp packets to pcap, can't just drop them...
            counter += 1
            droppedPkts += 1
        # print(counter, droppedPkts)#, tpkt.ip_src, tpkt.ip_proto)

    NS.ProcessFlows()
    NS.mergeModifiedPkts()
    NS.printFlowTable()
    print(NS.pktMerger.inQueue)
    print(len(NS.pktMerger.inQueue))
    #TestNetSploit(merger=NS.pktMerger)

    # Write to PCAP
    out_pcap = Path(oname)
    if out_pcap.is_file():
        os.remove(oname)
    for pkt in NS.pktMerger.inQueue:
        # if pkt.flow_tuple == (6, '192.168.10.14', 49474, '104.97.95.20', 443):
        #     print(pkt)
        pkt.write_pcap(oname)



if __name__ == "__main__":
    iname, oname = check_input()
    main(iname, oname)
