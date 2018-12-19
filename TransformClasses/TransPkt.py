from scapy.all import *
from enum import Enum

class TCP_FLAGS(Enum):
    FIN = 0x01 	# FIN flag in TCP.  check if set via: FIN & tcp_flags
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80
    DF = 0x02 	# don't fragment flag in IP. check if set via: DF & ip_flags

class TransPkt:
    def __init__(self, pkt):
        if not isinstance(pkt, scapy.layers.l2.Ether):
            print("ERROR: Attempting to initialize transPkt class with non-scapy packet")
            exit()
        self.pkt = pkt  # probaby don't want to do this
        self.update_5_tuple()

    # Getter: General Pkt Features
    @property
    def ts(self):
        return self.pkt.time
    @property
    def frame_len(self):
        return self.pkt.len

    # Getter: Ethernet Features
    @property
    def eth_src(self):
        return self.pkt[Ether].src
    @property
    def eth_dst(self):
        return self.pkt[Ether].dst

    # Getter: IP Features
    @property
    def ip_hdr(self):
        return self.pkt[IP].ihl
    @property
    def ip_len(self):
        return self.pkt[IP].len
    @property
    def ip_id(self):
        return self.pkt[IP].id
    @property
    def ip_flags(self):
        return self.pkt[IP].flags
    @property
    def ip_chksum(self):
        return self.pkt[IP].chksum
    @property
    def ip_src(self):
        return self.pkt[IP].src
    @property
    def ip_dst(self):
        return self.pkt[IP].dst
    @property
    def ip_proto(self):
        return self.pkt[IP].proto

    # Getter: TCP Features
    @property
    def src_port(self):
        return self.pkt[TCP].sport
    @property
    def dst_port(self):
        return self.pkt[TCP].dport
    @property
    def tcp_flags(self):
        return self.pkt[TCP].flags
    @property
    def seq_num(self):
        return self.pkt[TCP].seq
    @property
    def ack_num(self):
        return self.pkt[TCP].ack
    @property
    def tcp_chksum(self):
        return self.pkt[TCP].chksum

    # Getter: HTTP Features
    @property
    def http_pload(self):
        #print(self.pkt[Raw].load)
        if "Raw" in self.pkt:
            return self.pkt[Raw].load
        return None


    # Setter: General Packet Features
    @ts.setter
    def ts(self, ts):
        self.pkt.time = ts
    @frame_len.setter
    def frame_len(self, fLen):
        self.pkt.len = fLen

    # Setter: Ethernet Features
    @eth_src.setter
    def eth_src(self, src):
        self.pkt[Ether].src = src
    @eth_dst.setter
    def eth_dst(self, dst):
        self.pkt[Ether].dst = dst

    # Setter: IP Features
    @ip_hdr.setter
    def ip_hdr(self, hdr):
        self.pkt[IP].ihl = hdr
    @ip_len.setter
    def ip_len(self, len):
        self.pkt[IP].len = len
    @ip_id.setter
    def ip_id(self, id):
        self.pkt[IP].id = id
    @ip_chksum.setter
    def ip_chksum(self, chksum):
        self.pkt[IP].chksum = chksum
    @ip_src.setter
    def ip_src(self, src):
        self.pkt[IP].src = src
        self.update_5_tuple()
    @ip_dst.setter
    def ip_dst(self, dst):
        self.pkt[IP].dst = dst
        self.update_5_tuple()
    @ip_proto.setter
    def ip_proto(self, proto):
        self.pkt[IP].proto = proto
        self.update_5_tuple()

    # Setter: TCP Features
    @src_port.setter
    def src_port(self, sport):
        self.pkt[TCP].sport = sport
        self.update_5_tuple()
    @dst_port.setter
    def dst_port(self, dport):
        self.pkt[TCP].dport = dport
        self.update_5_tuple()
    @seq_num.setter
    def seq_num(self, seq):
        self.pkt[TCP].seq = seq
    @ack_num.setter
    def ack_num(self, ack):
        self.pkt[TCP].ack = ack
    @tcp_chksum.setter
    def tcp_chksum(self, chksum):
        self.pkt[TCP].chksum = chksum

    # Setter: HTTP Features
    @http_pload.setter
    def http_pload(self, pload):
        self.pkt[Raw].load = pload

    # Set TCP Flags
    def set_FIN(self):
        self.pkt[TCP].flags |= TCP_FLAGS.FIN.value
    def set_SYN(self):
        self.pkt[TCP].flags |= TCP_FLAGS.SYN.value
    def set_RST(self):
        self.pkt[TCP].flags |= TCP_FLAGS.RST.value
    def set_PSH(self):
        self.pkt[TCP].flags |= TCP_FLAGS.PSH.value
    def set_ACK(self):
        self.pkt[TCP].flags |= TCP_FLAGS.ACK.value
    def set_URG(self):
        self.pkt[TCP].flags |= TCP_FLAGS.URG.value
    def set_ECE(self):
        self.pkt[TCP].flags |= TCP_FLAGS.ECE.value
    def set_CWR(self):
        self.pkt[TCP].flags |= TCP_FLAGS.CWR.value
    def set_DF(self):
        self.pkt[IP].flags |= TCP_FLAGS.DF.value

    # Remove TCP Flags
    def unset_FIN(self):
        self.pkt[TCP].flags &= ~(1 << TCP_FLAGS.FIN.value - 1)
    def unset_SYN(self):
        self.pkt[TCP].flags &= ~(1 << TCP_FLAGS.SYN.value - 1)
    def unset_RST(self):
        self.pkt[TCP].flags &= ~(1 << TCP_FLAGS.RST.value - 1)
    def unset_PSH(self):
        self.pkt[TCP].flags &= ~(1 << TCP_FLAGS.PSH.value - 1)
    def unset_ACK(self):
        self.pkt[TCP].flags &= ~(1 << TCP_FLAGS.ACK.value - 1)
    def unset_URG(self):
        self.pkt[TCP].flags &= ~(1 << TCP_FLAGS.URG.value - 1)
    def unset_ECE(self):
        self.pkt[TCP].flags &= ~(1 << TCP_FLAGS.ECE.value - 1)
    def unset_CWR(self):
        self.pkt[TCP].flags &= ~(1 << TCP_FLAGS.CWR.value - 1)
    def unset_DF(self):
        self.pkt[IP].flags &= ~(1 << TCP_FLAGS.DF.value - 1)

    # Other Functions
    def update_5_tuple(self):
        self.flow_tuple = (self.pkt.proto, self.pkt[IP].src, self.pkt[TCP].sport, self.pkt[IP].dst, self.pkt[TCP].dport)

    # Write Packet to File (Append)
    def write_pcap(self, file):
        wrpcap(file, self.pkt, append=True)

    # Functions for Sorting
    def __lt__(self, other):
        return self.ts < other.ts
    def __le__(self, other):
        return(self.ts <= other.ts)
    def __repr__(self):
        return "Pkt({} @ ts: {}, ip_len: {}, ip_id: {}, seq_num: {}, ack_num: {}, pload: {})"\
            .format(self.flow_tuple, self.ts, self.ip_len, self.ip_id, self.seq_num, self.ack_num, str(self.http_pload))