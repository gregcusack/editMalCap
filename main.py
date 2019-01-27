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


    for pkt in pkts:
        tpkt = TransPkt(pkt)
        NS.loadFlowTable(tpkt)

    NS.ProcessFlows()

    print(NS.pktMerger.inQueue)
    #TestNetSploit(merger=NS.pktMerger)

    # TODO: uncomment.  this writes to pcap
    out_pcap = Path(oname)
    if out_pcap.is_file():
        os.remove(oname)
    for pkt in NS.pktMerger.inQueue:
        pkt.write_pcap(oname)



if __name__ == "__main__":
    iname, oname = check_input()
    main(iname, oname)
