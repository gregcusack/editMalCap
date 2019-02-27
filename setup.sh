#!/bin/bash
# README:
# $1: original pcap to modify
# $2: output pcap in which to store the flows for modification
# $3: output pcap in which to store the flows that need no modification

output=`python setup.py $1 $2 $3`

count=0
IFS="," read -ra ADDR <<< "$output"
for i in "${ADDR[@]}"; do
    if [ $count == 0 ]; then
    	echo "filtering using the following query: ""$i"
    	tshark -r $1 -Y "$i" -w $2
    else
	tshark -r $1 -Y "$i" -w $3
    fi
    count=$((count+1))
done

sleep 2

#`python main.py $2 $2`

#mergecap -w $4 $2 $3


