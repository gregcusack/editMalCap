from scapy.all import *

pkts = rdpcap("../NetSploit-files/pcaps/DAGMM/BruteForce/BruteForce_Thursday_toMod.pcap")
p3 = pkts[3]

p = Ether()
p[Ether].src = p3[Ether].src
p[Ether].dst = p3[Ether].dst
p[Ether].type = 0x800
p = p / IP(version=4, ihl=5, len=1000, id=1000, ttl=63, proto=6, tos=p3[IP].tos)
p = p / TCP(sport=44634, dport = 80, seq=p3[TCP].seq, ack=p3[TCP].ack, window=123123123)
p = p / Raw(load=p3[Raw].load)
# p3.show()

# field_names = []
# # Ether_field_names = [field.name for field in p[Ether].fields_desc]
# IP_field_names = [field.name for field in p[IP].fields_desc]
# TCP_field_names = [field.name for field in p[TCP].fields_desc]
# # field_names.append(Ether_field_names)
# field_names.append(IP_field_names)
# field_names.append(TCP_field_names)
# print(field_names)

# print(p[Ether])

# for field in IP_field_names:
# 	if field == "src":
# 		if p[


wrpcap("./test-pcap.pcap", p)

# for i in range(0,100):
# 	try:
# 		wrpcap("./test-pcap.pcap", p)
# 		# print(i)
# 	except struct.error:
# 		continue
	
# 	print(i)

