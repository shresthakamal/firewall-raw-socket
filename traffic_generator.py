import random
import os
import json
import sys

all_rules = {"L2": [], "L3V4": [], "L4TCP": [], "L4UDP": []}


def saveRules():
    filename = "rules.json"
    with open(filename, "w") as outfile:
        json.dump(all_rules, outfile)


# choice between two
binary = [0, 1]

# IP traffic attributes
Dest_Ip = "192.168.130.135"
TTL_options = [64, 128, 196, 255]
ToS_Values = [40, 80, 160, 320]

# UDP traffic attributes
Source_port_choices = [80, 53, 403]
Dest_port_choices = [80, 403, 5555]

# ICMP traffic attributes
Type_choices = [0, 3, 4, 5, 8]
Code_choices = [0, 1, 2, 3, 4, 5]

# TCP traffic attributes
syn_choices = [0, 1]
urg_choices = [0, 1]
rst_choices = [0, 1]
Source_port_choices_TCP = [80, 53, 403]
Dest_port_choices_TCP = [80, 403, 5555]

# Ethernet traffic attributes
Protocol_choices = [0, 1, 2, 3, 4, 5]

count = 1
if __name__ == "__main__":

    Purpose = sys.argv[1]
    if Purpose == "g":
        CreateRuleSet = 0
        WhileLoopInterations = 250
    elif Purpose == "rm":
        CreateRuleSet = 1
        WhileLoopInterations = sys.argv[2]

    for k in range(0, int(WhileLoopInterations)):

        # ******************************************************************************************************************************************
        # ******************************************************************************************************************************************
        # ******************************************************************************************************************************************

        # IP traffic
        TTL_selected = random.choice(TTL_options)
        Tos_value_selected = random.choice(ToS_Values)
        command = "nping -c 1 --delay 20ms --tcp -p 9876 --ttl " + str(TTL_selected) + " --tos " + str(Tos_value_selected) + " " + str(Dest_Ip)
        # print(command)
        if CreateRuleSet == 0:
            os.system(command)

        if CreateRuleSet == 1:
            rule_id = random.randint(1, 1000)

            binary_selected = random.choice(binary)
            if binary_selected == 1:
                Action = "Allow"
            else:
                Action = "Discard"

            rule_struct = {}
            rule_struct["rule_id"] = rule_id

            binary_selected = random.choice(binary)
            if binary_selected == 1:
                rule_struct["dstn_ip"] = "192.168.130.135"
            rule_struct["ipv4protocol"] = int(random.choice(Protocol_choices))
            rule_struct["rule"] = "Allow"
            all_rules["L3V4"].append(rule_struct)

        # ******************************************************************************************************************************************
        # ******************************************************************************************************************************************
        # ******************************************************************************************************************************************

        # UDP traffic
        Source_Port_Selected = random.choice(Source_port_choices)
        binary_selected = random.choice(binary)
        if binary_selected == 1:
            Dest_Port_Selected = random.choice(Dest_port_choices)
        else:
            Dest_Port_Selected = 9876
        command = "nping -c 1 --delay 20ms --udp -p " + str(Dest_Port_Selected) + " -g " + str(Source_Port_Selected) + " " + str(Dest_Ip)
        # print(command)

        if CreateRuleSet == 0:
            os.system(command)

        if CreateRuleSet == 1:
            rule_id = random.randint(1, 1000)

            binary_selected = random.choice(binary)
            if binary_selected == 1:
                Action = "Allow"
            else:
                Action = "Discard"

            rule_struct = {}
            rule_struct["rule_id"] = rule_id
            rule_struct["udpsrc_port"] = int(Source_Port_Selected)
            rule_struct["udpdest_port"] = int(Dest_Port_Selected)
            rule_struct["rule"] = "Allow"
            all_rules["L4UDP"].append(rule_struct)

        # ******************************************************************************************************************************************
        # ******************************************************************************************************************************************
        # ******************************************************************************************************************************************

        # TCP traffic
        Syn_selected = random.choice(syn_choices)
        if Syn_selected == 1:
            syn = "syn,"
        else:
            syn = ""

        URG_selected = random.choice(urg_choices)
        if URG_selected == 1:
            urg = "urg,"
        else:
            urg = ""

        rst = "rst"

        Source_Port_Selected_TCP = random.choice(Source_port_choices_TCP)
        Dest_Port_Selected_TCP = random.choice(Dest_port_choices_TCP)
        command = (
            "nping -c 1 --delay 20ms --tcp -g "
            + str(Source_Port_Selected_TCP)
            + " -p "
            + str(Dest_Port_Selected_TCP)
            + " --flags "
            + str(syn)
            + str(urg)
            + str(rst)
            + " "
            + str(Dest_Ip)
        )
        # print(command)

        if CreateRuleSet == 0:
            os.system(command)

        if CreateRuleSet == 1:
            rule_id = random.randint(1, 1000)

            binary_selected = random.choice(binary)
            if binary_selected == 1:
                Action = "Allow"
            else:
                Action = "Discard"

            rule_struct = {}
            rule_struct["rule_id"] = rule_id
            rule_struct["tcpsrc_port"] = int(Source_Port_Selected_TCP)
            rule_struct["tcpdest_port"] = int(Dest_Port_Selected_TCP)

            a = random.choice(binary)
            if a == 1:
                rule_struct["flag_urg"] = int(a)

            a = random.choice(binary)
            if a == 1:
                rule_struct["flag_syn"] = int(a)

            a = random.choice(binary)
            if a == 1:
                rule_struct["flag_rst"] = int(a)

            rule_struct["rule"] = "Allow"
            all_rules["L4TCP"].append(rule_struct)

        # ******************************************************************************************************************************************
        # ******************************************************************************************************************************************
        # ******************************************************************************************************************************************

        # Ethernet traffic
        protocol_selected = random.choice(Protocol_choices)
        binary_selected = random.choice(binary)
        if binary_selected == 1:
            Dest_mac = "52:54:00:f7:69:35"
        else:
            Dest_mac = ""

        binary_selected = random.choice(binary)
        if binary_selected == 1:
            Source_mac = "52:54:00:d6:10:87"
        else:
            Source_mac = ""

        command = "nping -c 1 --delay 20ms -arp " + " --dest-mac " + str(Dest_mac) + " -p " + " --source-mac " + str(Source_mac) + " " + str(Dest_Ip)
        # print(command)

        if CreateRuleSet == 0:
            os.system(command)

        if CreateRuleSet == 1:
            rule_id = random.randint(1, 1000)

            binary_selected = random.choice(binary)
            if binary_selected == 1:
                Action = "Allow"
            else:
                Action = "Discard"

            rule_struct = {}
            rule_struct["rule_id"] = rule_id
            if Source_mac != "":
                rule_struct["src_mac"] = Source_mac
            if Dest_mac != "":
                rule_struct["dstn_mac"] = Dest_mac
            rule_struct["rule"] = "Allow"
            all_rules["L2"].append(rule_struct)

    if CreateRuleSet == 1:
        saveRules()
