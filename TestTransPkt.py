from scapy.all import *
from TransPkt import TransPkt

class TestTransPkt:
    def __init__(self, tPkt, sPkt):
        if not isinstance(tPkt, TransPkt) or not isinstance(sPkt, scapy.layers.l2.Ether):
            print("ERROR: Invalid types passed in.  Must be TransPkt and ScapyPkt")
            exit()
        self.tPkt = tPkt
        self.sPkt = sPkt

    def run_test(self):
        # Assert general pkt features
        assert self.tPkt.ts == self.sPkt.time
        assert self.tPkt.frame_len == len(self.sPkt)

        # Assert Ethernet Features
        assert self.tPkt.eth_src == self.sPkt[Ether].src
        assert self.tPkt.eth_dst == self.sPkt[Ether].dst

        # Assert IP Features
        assert self.tPkt.ip_hdr == self.sPkt[IP].ihl
        assert self.tPkt.ip_len == self.sPkt[IP].len
        assert self.tPkt.ip_flags == self.sPkt[IP].flags
        assert self.tPkt.ip_chksum == self.sPkt[IP].chksum
        assert self.tPkt.ip_src == self.sPkt[IP].src
        assert self.tPkt.ip_dst == self.sPkt[IP].dst
        assert self.tPkt.ip_proto == self.sPkt[IP].proto

        # Assert TCP Features
        assert self.tPkt.src_port == self.sPkt[TCP].sport
        assert self.tPkt.dst_port == self.sPkt[TCP].dport
        assert self.tPkt.seq_num == self.sPkt[TCP].seq
        assert self.tPkt.ack_num == self.sPkt[TCP].ack
        assert self.tPkt.tcp_chksum == self.sPkt[TCP].chksum

        # Assert HTTP Features
        if Raw in self.sPkt:
            assert self.tPkt.http_pload == self.sPkt[Raw].load