from statistics import stdev, mean
import numpy as np
from scipy.stats import truncnorm
from collections import namedtuple
from scapy.all import *


# x = [0,2,4,5,10,13,20]
# for i in range(len(x)):
# 	#i += 1
# 	if i == len(x):
# 		print(":breakiung")
# 		break
# 	print(i)

d = {}
d['a.1'] = ["a.1","a.1","a.1","a.1","a.2","a.2","a.2","a.2","a.2","a.3","a.3","a.3","a.3","a.3"]
d['b.1'] = ["b.1","b.1","b.1","b.1","b.1","b.1","b.1","b.1","b.1"]

print(d)

# tmp = {}
# for k,v in d.items():
# 	for i in v:
# 		if i not in tmp:
# 			tmp[i] = []
# 		tmp[i].append(i)

# print(tmp)

v = d["a.1"]
print(v)

del d["a.1"]

for pkt in v:
	if pkt not in d:
		d[pkt] = []
	d[pkt].append(pkt)
	print(pkt)

print(d)


