# How to Run #
1) `./setup.sh $1 $2 $3`<br/>
    * $1: original pcap to modify
    * $2: output pcap in which to store the flows for modification
    * $3: output pcap in which to store the flows that need no modification
2) Run:<br/>
    `python3 main.py $2 $4`<br/>
    * $4: output pcap for transformed flows
3) From cmdline, run:<br/>
    `mergecap -w $5 $4 $3`
    * $5: pcap to store adversarial pcap!


# Config.json #
- times are in ms
- IA times
    - max/min are optional
    - default values
        - min: 0
        - max: original flow's maxIA
    - best effort approach
        - cannot guarantee exact IA time match
        - new IA times are generated via a truncated normal distribution
            - the more pkts in the flow, the closer the IA times will match the desired values
    - in order to get desired flow duration, set 
# TODO
* add intro
* put config file details after intro
* fix so don't require 3 pcaps to write to
            
            
Dependencies:
numpy
scapy
scipy
