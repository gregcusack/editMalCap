from scapy.all import *
from TransformClasses.TransPkt import TransPkt
from TestClasses.TestTransPkt import TestTransPkt
from NetSploit import NetSploit
from Config import Config

from pathlib import Path
from os import remove

def check_input():
    if len(sys.argv) != 4:
        print("Error: Need to specify input pcap to edit, output pcap filename, and json file with flows")
        print("e.g. python edit.py <input.pcap> <output.pcap> <flows.json>")
        exit()

    return sys.argv[1], sys.argv[2], sys.argv[3]



def main(iname, oname, flows_json):
    print("Reading in PCAP...")
    pkts = rdpcap(iname)

    attack = iname.split("/")
    attack = attack[-1:]
    attack = attack[0].split("_")
    attack = attack[0]
    print("attack: {}".format(attack))

    # config = Config("config.json")
    config = Config(flows_json)
    NS = NetSploit(config, attack)

    counter = 0
    droppedPkts = 0
    print("Loading PCAPs into Flow Table...")
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

    print("Processing Flows...")
    NS.ProcessFlows()
    print("Merging Modified Packets...")
    NS.mergeModifiedPkts()

    print("Testing Flow Length Transformation Results...")
    NS.run_flow_transformation_test()



    # NS.printFlowTable()
    # print(NS.pktMerger.inQueue)
    # print(len(NS.pktMerger.inQueue))
    #TestNetSploit(merger=NS.pktMerger)

    # Write to PCAP
    print("Writing back files to PCAP")
    out_pcap = Path(oname)
    if out_pcap.is_file():
        os.remove(oname)
    for pkt in NS.pktMerger.inQueue:
        # if pkt.flow_tuple == (6, '192.168.10.15', 52854, '205.174.165.73', 8080):
        #     print(pkt)
        # print(pkt)
        pkt.write_pcap(oname)



if __name__ == "__main__":
    iname, oname, flows_json = check_input()
    main(iname, oname, flows_json)
