Main Category       Header Type         Header name         Header value Type           Possible values

L2                  Ethernet            rule_id             int                         any integer
                                        src_mac             string                      Any mac address
                                        dstn_mac            string                      Any mac address
                                        rule                string                      Allow / Discard


L3V4                IP                  rule_id             int                         any integer
                                        src_ip              string                      Any IP address
                                        dstn_ip             string                      Any IP address
                                        ipv4protocol        int                         Protocol number (1 for  ICMP)
                                        rule                string                      Allow / Discard


L4TCP               TCP                 rule_id             int                         any integer
                                        tcpsrc_port         int                         any allowed port number
                                        tcpdest_port        int                         any allowed  port number
                                        flag_urg            int                         0/1
                                        flag_syn            int                         0/1
                                        flag_rst            int                         0/1
                                        rule                string                      Allow / Discard


L4UDP               UDP                 rule_id             int                         any integer
                                        udpsrc_port         int                         any allowed port number
                                        udpdest_port        int                         any allowed port number
                                        rule                string                      Allow / Discard
_________________________________________________________________________________________________________________________________________________________________________
************************************************************************************************************************************************************************
Initial rule set : {"L2" : [], "L3V4" : [], "L4TCP" : [], "L4UDP" :[]}

1.
Let you  want to add L4TCP filter to match "tcpdest_port = 9876, flag_syn =  1 and flag_rst =  0".
Choose random rule id, let 768. And we want to allow matching packet.

Updated rule set as: {"L2" : [],
                    "L3V4" : [], 
                    "L4TCP" : [{"rule_id": 768, "tcpdest_port": 9876, "flag_syn" : 1, "flag_rst" : 0, "rule":"Allow"}],
                    "L4UDP" :[]}

2.
Let you want to add one more filter to allow under same category L4TCP for  rule_id = 9, tcpsrc_port = 80

Updated rule set as: {"L2" : [],
                    "L3V4" : [], 
                    "L4TCP" : [{"rule_id": 768, "tcpdest_port": 9876, "flag_syn" : 1, "flag_rst" : 0, "rule":"Allow"}, 
                               {{"rule_id": 9, "tcpsrc_port": 80, "rule":"Allow"}] ,
                    "L4UDP" :[]}

3
If you want to add filter for L2 to  discard traffic having src_mac =  with rule_id = 62 
Updated rule set as: {"L2" : [{"rule_id": 62, "src_mac": "11:22:33:44:55:66", "rule":"Discard"}],
                     "L3V4" : [], 
                    "L4TCP" : [{"rule_id": 768, "tcpdest_port": 9876, "flag_syn" : 1, "flag_rst" : 0, "rule":"Allow"}, 
                               {{"rule_id": 9, "tcpsrc_port": 80, "rule":"Allow"}] ,
                     "L4UDP" :[]}