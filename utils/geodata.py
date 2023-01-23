#!/bin/env python3

# Geodata Creation
# ------------------------------------------
#   Author    : SonyaCore
# 	Github    : https://github.com/SonyaCore
#   Licence   : https://www.gnu.org/licenses/gpl-3.0.en.html

import re
import json
import ipaddress
import os, sys
from urllib.request import urlopen, Request
from typing import Iterable


class DataSet:
    CIDR = Request("https://cdn-lite.ip2location.com/datasets/IR.json")
    ADS = Request("https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt")
    sets = []
    ads = []
    cidrs = []
    name = ""

URL_REGEX = re.compile(
r"\b((?:https?://)"
r"?(?:(?:www\.)"
r"?(?:[\da-z\.-]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]"
r"(?!(?:10|127)(?:\.\d{1,3}){3})"
r"(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})"
r"(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})"
r"[0-4][0-9][01]?[0-9][0-9]?)\.)(?:25"
r"|"
r"2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:)"
r"{7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:"
r"[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]"
r"{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]"
r"{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]"
r"{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]"
r"{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]"
r"{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4})"
r"{1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}"
r"|"
r"::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]"
r"|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]"
r"|"
r"(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:)"
r"{1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.)"
r"{3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))"
r"(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]"
r"{2}|655[0-2][0-9]|6553[0-5])?(?:/[\w\.-]*)*/?)\b",
re.UNICODE | re.IGNORECASE
)


def load_dataset():

    with urlopen(DataSet.CIDR) as respone:
        data = respone.read()

    dat = json.loads(data)

    for item in dat["data"]:
        start = ipaddress.IPv4Address(item[:2][0])
        end = ipaddress.IPv4Address(item[:2][1])
        DataSet.cidrs.append(next(ipaddress.summarize_address_range(start, end)))
    for _, datasets in enumerate(DataSet.cidrs):
        with open("/tmp/dump", "a") as file:
            file.write(str(datasets) + "\n")


def url(text: str) -> bool:
    return bool(URL_REGEX.search(text))


def load_ads() -> Iterable[str]:
    with urlopen(DataSet.ADS) as respone:
        data = respone.read().decode("utf-8")

    ads = re.sub(r"(?m)^\s*#.*\n?", "", data)
    ads = data.splitlines()[1:]
    ads = filter(url, ads)

    DataSet.ads = [domain for domain in ads if URL_REGEX.match(domain)]
    return sorted(DataSet.ads)


def qv2rayrouting(cidr: list, ads: list):
    schema = {
        "description": "List of Iranian IP's",
        "domainStrategy": "IPIfNonMatch",
        "domains": {"block": ["geosite:category-ads-all"]},
        "domains": {"direct": ads},
        "ips": {"direct": cidr},
        "name": "IR_IPS",
    }
    return json.dumps(schema, indent=2)


def clash(cidr: list, ads: list) -> str:
    config = (
        "# Clash\n"
        "# Wiki: https://github.com/Dreamacro/clash/wiki/premium-core-features#rule-providers\n"
        "payload:\n"
    )
    config += "".join(f"  - DOMAIN-SUFFIX,{adslist}\n" for adslist in ads)
    config += "".join(f"  - IP-CIDR,{cidrlist}\n" for cidrlist in cidr)
    config += "  - GEOIP,IR\n"
    return config


def loadsets():
    global cidrs, ads
    with open("/tmp/dump", "r") as cidr:
        cidrs = [line.strip() for line in cidr]
    with open("/tmp/ads", "r") as ads:
        ads = [line.strip() for line in ads]


def writerouting(name: json):
    loadsets()
    with open(name, "w") as file:
        file.write(qv2rayrouting(cidrs, ads))


def writeclash(name: json):
    loadsets()
    with open(name, "w") as file:
        file.write(clash(cidrs, ads))


def writeraw(cidr,ads):
    with open("/tmp/ads", "r") as file:
        data = file.read()
    with open(ads, "w") as ads:
        ads.write(data)      
    with open("/tmp/dump", "r") as file:
        data = file.read()
    with open(cidr, "w") as cidr:
        cidr.write(data)


try:
    load_dataset()
    load_ads()
    with open("/tmp/dump", "w") as file:
        for v, datasets in enumerate(DataSet.cidrs):
            file.write(str(datasets) + "\n")
    with open("/tmp/ads", "w") as file:
        for v, ads in enumerate(DataSet.ads):
            file.write(str(ads) + "\n")

    if sys.argv[1] in ("qv2ray", "q2ray"):
        DataSet.name = "qv2ray-client.json"
        writerouting(DataSet.name)

    elif sys.argv[1] in ("raw", "ip", "ips"):
        writeraw("IranIPs.txt","ads.txt")

    elif sys.argv[1] in ("clash", "clashyaml", "c"):
        DataSet.name = "clash_rules.yaml"
        writeclash(DataSet.name)

except IndexError:
    sys.exit("No Option Selected")
finally:
    for paths in ["/tmp/dump", "/tmp/ads"]:
        os.remove(paths)

    print("Generated {}".format(DataSet.name))
    print("Total CIDR'S : {}".format(len(DataSet.cidrs)))
    print("Total Domain ADS : {}".format(len(DataSet.ads)))