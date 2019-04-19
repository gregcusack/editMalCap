from scapy.all import *
from Config import Config
from pathlib import Path
from os import remove
import json
import subprocess

def check_input():
    if len(sys.argv) != 4:
        print("Error: Need to specify input pcap to edit and output pcaps to store flows to be modified and unmodified flows")
        print("e.g. python edit.py <input.pcap> <outputMOD.pcap> <outputUNMOD.pcap>")
        exit()

    return sys.argv[1], sys.argv[2], sys.argv[3]

def gen_tshark_filter(iname, onameMOD, onameUNMOD, config):
    query = ""
    with open(config) as f:
        for key in f:
            key = key[:-1].split(',')

            proto = "ip.proto == " + key[0]
            srcIP = "ip.src == " + key[1]
            dstIP = "ip.dst == " + key[3]

            if key[0] == "6":
                srcPort = "tcp.srcport == " + key[2]
                dstPort = "tcp.dstport == " + key[4]
            elif key[0] == "17":
                srcPort = "udp.srcport == " + key[2]
                dstPort = "udp.dstport == " + key[4]
            else:
                print("Error: Invalid protocol number entered in " + config)
                exit()

            query += ("(" + proto + " and " + srcIP + " and " + srcPort + " and " + dstIP + " and " + dstPort + ") or ")

            # now get biflow query
            srcIP = "ip.src == " + key[3]
            dstIP = "ip.dst == " + key[1]
            if key[0] == "6":
                srcPort = "tcp.srcport == " + key[4]
                dstPort = "tcp.dstport == " + key[2]
            elif key[0] == "17":
                srcPort = "udp.srcport == " + key[4]
                dstPort = "udp.dstport == " + key[2]
            else:
                print("Error: Invalid protocl number entered in " + config)
                exit()

            query += ("(" + proto + " and " + srcIP + " and " + srcPort + " and " + dstIP + " and " + dstPort + ") or ")

        query = query[:-4]# + "-"
        notquery = "not (" + query + ")"
        return query, notquery






def main(iname, onameMOD, onameUNMOD):
    # pkts = rdpcap(iname)

    # config = Config("config.json")
    q, notq = gen_tshark_filter(iname, onameMOD, onameUNMOD, "flows-to-extract.txt")
    print(q + "," + notq)


if __name__ == "__main__":
    iname, onameMOD, onameUNMOD = check_input()
    main(iname, onameMOD, onameUNMOD)
