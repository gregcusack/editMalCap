from scapy.all import *

splits = 1
ts = [0,0,20]
k = 0
i = base_index = 2

while len(ts) <= 100:
	i = base_index
	k = 0
	while k < splits:
		print(k, len(ts), splits, i)
		if ts[i] > 1:
			x = ts[i] // 2
			ts.insert(i+1,x)
			ts[i] = ts[i] // 2
			i += 2
		else:
			i += 1
		print(ts)
		k += 1	
	splits *= 2


