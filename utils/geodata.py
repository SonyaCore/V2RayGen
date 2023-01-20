#!/bin/env python3

# Geodata Creation
# ------------------------------------------
#   Author    : SonyaCore
# 	Github    : https://github.com/SonyaCore
#   Licence   : https://www.gnu.org/licenses/gpl-3.0.en.html

import json
import ipaddress
import os , sys
from urllib.request import urlopen, Request

class DataSet:
    URL = Request("https://cdn-lite.ip2location.com/datasets/IR.json")
    sets = []
    cidrs = list(sets)
    name = ""

def load_dataset():

    with urlopen(DataSet.URL) as respone :
        data = respone.read()

    dat = json.loads(data)

    for item in dat["data"]:
        start = ipaddress.IPv4Address(item[:2][0])
        end = ipaddress.IPv4Address(item[:2][1])
        DataSet.cidrs.append(next(ipaddress.summarize_address_range(start, end)))
    for v , datasets in enumerate(DataSet.cidrs) :
        with open('/tmp/dump',"a") as file:
            file.write(str(datasets) + "\n")


def qv2rayrouting(dataset : list):
    schema = {
        "description" : "List of Iranian IP's",
        "domainStrategy" : "IPIfNonMatch",
        "domains": {
            "block": [
        "geosite:category-ads-all" ]
        },
        "ips": { "direct": dataset },
        "name": "IR_IPS"
    }
    return json.dumps(schema,indent=2)

def writerouting(name : json):
    load_dataset()
    template =  open("/tmp/dump","r").read().split()
    with open(name,"w") as file:
        file.write(qv2rayrouting(template))
    os.remove("/tmp/dump")

def writeraw(name):
    load_dataset()
    template =  open("/tmp/dump","r").read()
    with open(name , "w") as fp :
        fp.write(template)
    os.remove("/tmp/dump")
    
try :
    if sys.argv[1] in ("qv2ray" , "q2ray"):
        DataSet.name = "qv2ray-client.json"
        writerouting(DataSet.name)
    elif sys.argv[1] in ("raw" , "ip" , "ips"):
        DataSet.name = "IranIPs.txt"
        writeraw(DataSet.name) 
except IndexError :
    sys.exit("No Option Selected")
finally :
    print("Generated {}".format(DataSet.name))
    print("Total CIDR'S : {}".format(len(DataSet.cidrs)))