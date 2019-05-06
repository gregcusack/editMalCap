*** Config.json ***
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
            
            
Dependencies:
numpy
scapy
scipy