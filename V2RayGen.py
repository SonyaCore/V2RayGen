#!/usr/bin/env python3

# XRay Config Generator
# ------------------------------------------
#   Author    : SonyaCore
# 	Github    : https://github.com/SonyaCore
#   Licence   : https://www.gnu.org/licenses/gpl-3.0.en.html

import os
import sys
import subprocess
import time
import uuid
import argparse
import base64
import json
import random
import string
import csv
import re
import platform
import ipaddress
from urllib.parse import unquote
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from http.client import RemoteDisconnected
from binascii import Error

# -------------------------------- Constants --------------------------------- #

# Name
NAME = "XRayGen"

# Version
VERSION = "1.1.8"

# UUID Generation
UUID = uuid.uuid4()

# Config Name
CONFIGNAME = "config.json"
OBFS = "docker-compose.yml"

SELFSIGEND_CERT = "host.cert"
SELFSIGEND_KEY = "host.key"

# PORT
PORT = 80

# TLS
TLSTYPE = "none"

# Docker Compose FILE
DOCKERCOMPOSE = "docker-compose.yml"

# Client Side PORT
SOCKSPORT = 10808
HTTPPORT = 10809

## AGENT
AGENT_URL = "https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/XRayAgent.py"
AGENT_PATH = "/tmp/agent.py"

# -------------------------------- Colors --------------------------------- #

# Color Format
green = "\u001b[32m"
yellow = "\u001b[33m"
blue = "\u001b[34m"
error = "\u001b[31m"
reset = "\u001b[0m"

# -------------------------------- Argument Parser --------------------------------- #

usage = "python3 {} {} <protocol> {} {} <optional args> {}".format(
    NAME, error, reset, blue, reset
)
formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=64)
parser = argparse.ArgumentParser(prog=NAME, formatter_class=formatter, usage=usage)


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif v.lower() in ("no", "false", "f", "n", "0"):
        return False
    else:
        raise argparse.ArgumentTypeError("Boolean value expected.")


parser.add_argument("--config", "-c", action="store_true", help="Creating only the Configuration file")
parser.add_argument("--agent", "-a", action="store_true", help="Launch XRayAgent")
parser.add_argument("--protocols", "-l", action="store_true", help="Show list of protocols")


quick = parser.add_argument_group("{}Protocols{}".format(green, reset))

quick.add_argument("--vmess", "-vm", action="store_true", help="Create VMess")
quick.add_argument("--vless", "-vl", action="store_true", help="Create VLess")
quick.add_argument("--trojan", "-tr", action="store_true", help="Create Trojan")
quick.add_argument("--shadowsocks", "-ss", action="store_true", help="Create ShadowSocks")

logdnsparser = parser.add_argument_group(
    "{}XRay - Log & DNS Settings{}".format(green, reset)
)

logdnsparser.add_argument(
    "--loglevel",
    "-log",
    action="store",
    type=str,
    metavar="",
    help="Loglevel for Xray config. default: [warning]",
)
logdnsparser.add_argument(
    "--dns", action="store", type=str, metavar="", help="Optional DNS. default: [nodns]"
)

routingparser = parser.add_argument_group("{}XRay - Routing{}".format(green, reset))
routingparser.add_argument(
    "--block",
    "--block-routing",
    action="store_true",
    help="Blocking Bittorrent and Ads in configuration. [default: False]",
)
routingparser.add_argument(
    "--blockir",
    "--block-ir",
    action="store_true",
    help="Blocking Bittorrent, Ads and Irnian IPs in configuration. [default: False]",
)

inboundsparser = parser.add_argument_group("{}XRay - Inbounds{}".format(green, reset))
inboundsparser.add_argument(
    "--tls", "-t", action="store_true", help="Using TLS in specified protocol"
)
inboundsparser.add_argument(
    "--xtls", "-xt", action="store_true", help="Using XTLS in specified protocol"
)


inboundsparser.add_argument(
    "--port",
    "-p",
    action="store",
    type=int,
    metavar="",
    help="Optional PORT for Xray Config. defualt: [80,443]",
)
inboundsparser.add_argument(
    "--uuid",
    "-u",
    action="store",
    type=str,
    metavar="",
    help="Optional UUID / ID for configuration. default: [random]",
    default=UUID,
)
inboundsparser.add_argument(
    "--alterid",
    "-id",
    action="store",
    type=int,
    metavar="",
    help="Optional alterId for configuration. default: [0]",
    default=0,
)
inboundsparser.add_argument(
    "--insecure",
    "--insecure-encryption",
    action="store",
    type=str2bool,
    nargs="?",
    metavar="",
    const=True,
    help="Disable Insecure Encryption. default: [True]",
    default=True,
)
streamsettingsparser = parser.add_argument_group(
    "{}XRay - Stream Settings{}".format(green, reset)
)
# streamsettingsparser.add_argument(
#     "--http",
#     "--http-stream",
#     action="store_true",
#     help="Using HTTP network stream. default: [WebSocket]",
# )

streamsettingsparser.add_argument(
    "--tcp",
    "--tcp-stream",
    action="store_true",
    help="Using TCP network stream. default: [WebSocket]",
)

streamsettingsparser.add_argument(
    "--wspath",
    "--websocket-path",
    action="store",
    type=str,
    metavar="",
    help="Optional WebSocket path. default: [/graphql]",
    default="/graphql",
)

streamsettingsparser.add_argument(
    "--header",
    "--http-header",
    action="store",
    type=argparse.FileType("r"),
    metavar="",
    help="Optional JSON HTTPRequest Header.",
)

linkparser = parser.add_argument_group(
    "{}XRay - Link Configuration{}".format(green, reset)
)

linkparser.add_argument(
    "--linkname",
    "-ln",
    action="store",
    type=str,
    metavar="",
    help="Name for Xray generated link. default: [xray]",
)
linkparser.add_argument(
    "--qrcode",
    "-qr",
    action="store_true",
    help="Generate QRCode for generated link.",
)

client = parser.add_argument_group("{}XRay Client Configuration{}".format(green, reset))

client.add_argument(
    "--security",
    "--client-security",
    action="store",
    type=str,
    metavar="",
    help="Security for Client-side JSON config. default: [auto]",
)

client.add_argument(
    "--csocks",
    "--clientsocks",
    action="store",
    type=int,
    metavar="",
    help="SOCKS port for Client-Side JSON config. default: [{}]".format(SOCKSPORT),
)
client.add_argument(
    "--chttp",
    "--clienthttp",
    action="store",
    type=int,
    metavar="",
    help="HTTP port for Client-Side JSON config. default: [{}]".format(HTTPPORT),
)

shadowsocks = parser.add_argument_group("{}ShadowSocks{}".format(green, reset))

shadowsocks.add_argument(
    "--sspass",
    "--shadowsocks-password",
    action="store",
    type=str,
    metavar="",
    help="Set Password for ShadowSocks. default: [random]",
)

shadowsocks.add_argument(
    "--ssmethod",
    "--shadowsocks-method",
    action="store",
    type=str,
    metavar="",
    help="Set Method for ShadowSocks. default: [2022-blake3-chacha20-poly1305]",
)

trojan = parser.add_argument_group("{}Trojan{}".format(green, reset))
trojan.add_argument(
    "--tpass",
    "--trojan-password",
    action="store",
    type=str,
    metavar="",
    help="Set Password for Trojan. default: [random]",
)

docker = parser.add_argument_group("{}Docker{}".format(green, reset))

docker.add_argument(
    "--v2ray",
    "-v2",
    action="store_true",
    required=False,
    help="Use V2Ray insted of XRay",
)

docker.add_argument(
    "--dockerfile",
    action="store_true",
    required=False,
    help="Generate xray-core docker-compose file",
)

docker.add_argument(
    "--ssdocker",
    "--shadowsocks-dockerfile",
    action="store_true",
    required=False,
    help="Generate ShadowSocks docker-compose file for shadowsocks-libev",
)

docker.add_argument(
    "--dockerup",
    action="store_true",
    required=False,
    help="Start docker-compose in system",
)

parseurl = parser.add_argument_group("{}Link Parse{}".format(green, reset))

parseurl.add_argument(
    "--parse",
    "--parseurl",
    action="store",
    type=str,
    metavar="",
    help="Parse encoded link. supported formats: [vmess://,ss://]",
)

parseurl.add_argument(
    "--parseconfig",
    "--readconfig",
    action="store",
    type=argparse.FileType("r"),
    metavar="",
    help="Parse Configuration file",
)

firewall = parser.add_argument_group("{}Firewall{}".format(green, reset))

firewall.add_argument(
    "--firewall",
    "-fw",
    action="store_true",
    help="Adding firewall rules after generating configuration",
)

inboundsparser = parser.add_argument_group("{}Google BBR{}".format(green, reset))
routingparser.add_argument(
    "--bbr",
    action="store_true",
    help="Installing Google BBR on the server. [default: False]",
)

# xray.add_argument(
#     "--domain",
#     "--domain-websocket",
#     action="store",
#     type=str,
#     metavar="",
#     help="Use Domain insted of IP for WebSocket. default: [ServerIP]",
# )

opt = parser.add_argument_group("{}info{}".format(green, reset))
opt.add_argument("-v", "--version", action="version", version="%(prog)s " + VERSION)

# Arg Parse
args = parser.parse_args()

# ------------------------------ Miscellaneous ------------------------------- #

# Banner
def banner(t=0.0005):
    data = """{}
 __   __ _____              _____            
 \ \ / /|  __ \            / ____|           
  \ V / | |__) |__ _ _   _| |  __  ___ _ __  
   > <  |  _  // _` | | | | | |_ |/ _ \ '_ \ 
  / . \ | | \ \ (_| | |_| | |__| |  __/ | | |
 /_/ \_\|_|  \_\__,_|\__, |\_____|\___|_| |_|
                     __/ |                  
                    |___/                   
{}""".format(
        green, reset
    )
    for char in data:
        sys.stdout.write(char)
        time.sleep(t)
    sys.stdout.write("\n")
    sys.stdout.write("Version: " + VERSION)
    sys.stdout.write("\n")


def python_version():
    if sys.version_info < (3, 5):
        raise Exception(
            "Your Python version is too old. Please upgrade to version 3.5 or later."
        )
    else:
        pass


def user_permission() -> None:
    if os.getuid() == 0:
        PRIVILEGE = green + "GRANTED" + reset
        t = True
    else:
        PRIVILEGE = error + "DENIED" + reset
        t = False
        pass
    print("ROOT PRIVILEGE : {}".format(PRIVILEGE))
    if t == False:
        print(
            yellow
            + "WARNING : Some sections might not work without root permission"
            + reset
        )


def docker_compose_version() -> str:
    if sys.version_info < (3, 6):
        return "v2.16.0"
    else:
        tag = "latest"
        version = "name"
        compose = Request(
            "https://api.github.com/repos/docker/compose/releases/{}".format(tag),
            headers={
                "User-Agent": "Mozilla/5.0",
            },
        )
        with urlopen(compose) as response:
            return json.loads(response.read().decode())[version]


# Return IP
def ip():
    """
    return actual IP of the server.
    if there are multiple interfaces with private IP the public IP will be used for the config
    """
    try:
        url = "http://ip-api.com/json/?fields=query"
        httprequest = Request(url, headers={"Accept": "application/json"})

        with urlopen(httprequest) as response:
            data = json.loads(response.read().decode())
            return data["query"]
    except HTTPError:
        print(
            error
            + "failed to send request to {} please check your connection".format(
                url.split("/json")[0]
            )
            + reset
        )
        sys.exit(1)


def get_random_charaters(length=24):
    """
    Get random password pf length with letters, digits, and symbols
    """

    characters = string.ascii_letters + string.digits
    password = "".join(random.choice(characters) for i in range(length))

    return password


def country():
    """
    return Country Code of the server.
    country code are used for detecting server location
    if server are not in the filtered list nginx template will be generated
    """
    try:
        countrycode = get_country()
        if countrycode not in ("IR", "CN", "VN"):
            print(
                yellow
                + "\n! You Are Using External Server [{}]\n".format(countrycode)
                + "Nginx Template:"
                + reset
            )
            print(nginx())
            print(yellow + "! Append to /etc/nginx/nginx.conf" + reset)
    except HTTPError:
        print(
            error
            + "failed to send request to {} please check your connection".format(
                countrycode.split("/json")[0]
            )
            + reset
        )
        sys.exit(1)


def get_country() -> str:
    """
    return Country Code of the server.
    """
    countrycode_url = "http://ip-api.com/json/?fields=countryCode"
    httprequest = Request(countrycode_url, headers={"Accept": "application/json"})

    with urlopen(httprequest) as response:
        data = json.loads(response.read().decode())

    return data["countryCode"]


def dnsselect():
    """
    DNS Selection.
    dnsselect are used for set a dns to the generated config
    https://www.v2ray.com/en/configuration/dns.html#dnsobject
    """
    global dnslist, NODNS, dnsserver
    dnslist = ["both", "google", "cloudflare", "opendns", "quad9", "adguard", "nodns"]

    dnsserver = {}
    dnsserver[
        0
    ] = """"dns": {
      "servers": [
        "8.8.8.8",
        "1.1.1.1",
        "4.2.2.4"
    ]
  },"""
    dnsserver[
        1
    ] = """"dns": {
      "servers": [
        "8.8.8.8",
        "4.2.2.4"
    ]
  },"""
    dnsserver[
        2
    ] = """"dns": {
      "servers": [
        "1.1.1.1"
    ]
  },"""

    dnsserver[
        3
    ] = """"dns": {
      "servers": [
        "208.67.222.222",
        "208.67.220.220"
    ]
  },"""

    dnsserver[
        4
    ] = """"dns": {
      "servers": [
        "9.9.9.9",
        "149.112.112.112"
    ]
  },"""

    dnsserver[
        5
    ] = """"dns": {
      "servers": [
        "94.140.14.14",
        "94.140.15.15"
    ]
  },"""

    NODNS = ""


def get_distro() -> str:
    """
    return distro name based on os-release info
    """
    RELEASE_INFO = {}
    with open("/etc/os-release") as f:
        reader = csv.reader(f, delimiter="=")
        for row in reader:
            if row:
                RELEASE_INFO[row[0]] = row[1]

    return "{}".format(RELEASE_INFO["NAME"])


def create_key():
    """
    create self signed key with openssl
    """
    random_domain = get_random_charaters(8)
    countrycode = get_country()
    print(green)
    subprocess.run(
        "openssl req -new -newkey rsa:4096 -days 735 -nodes -x509 \
    -subj '/C={}/ST=Denial/L=String/O=Dis/CN=www.{}.{}' -keyout {} -out {}".format(
            countrycode, random_domain, countrycode, SELFSIGEND_KEY, SELFSIGEND_CERT
        ),
        shell=True,
        check=True,
    )
    print(reset)


def clearcmd() -> None:
    version = platform.system()
    if version in ("Linux", "Darwin"):
        subprocess.run("clear")
    elif version == "Windows":
        subprocess.run("cls")


# def websocket_domaincheck(url = args.domain,t = 10) :
#     """
#     when using the domain for WebSocket the status code should be 400
#     else exception will occur.
#     """
#     try:
#         response = urlopen(f'{args.domain}{args.wspath}',timeout= t)

#     except HTTPError as error:
#         response_code = error.code
#         print( blue + 'Domain status : '+ reset + str(response_code))
#         if response_code == 400:
#             return True
#         else:
#             raise URLError(error.reason)


def validate_email(email):
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    if re.fullmatch(regex, email):
        pass
    else:
        sys.exit(
            error
            + "ERROR : Invalid Email"
            + reset
            + " Please enter a valid email address"
        )


def install_bbr() -> None:
    subprocess.run(
        "curl https://raw.githubusercontent.com/SonyaCore/across/master/bbr.sh | bash -",
        shell=True,
        check=True,
    )


def openssl_rand(type, byte) -> str:
    return (
        subprocess.check_output("openssl rand -{} {}".format(type, byte), shell=True)
        .decode("utf-8")
        .strip("\n")
    )


def launch_agent():
    clearcmd()
    subprocess_command = "curl -s {url} --output {path} && python3 {path}".format(
        url=AGENT_URL, path=AGENT_PATH
    )
    subprocess.run(subprocess_command, check=True, shell=True)
    os.remove(AGENT_PATH)


# -------------------------------- Global Variables --------------------------------- #

if args.v2ray:
    PROTOCOL = "v2ray"
else:
    PROTOCOL = "xray"

# Certificate location
crtkey = "/etc/{}/{}".format(PROTOCOL, SELFSIGEND_CERT)
hostkey = "/etc/{}/{}".format(PROTOCOL, SELFSIGEND_KEY)

# Outband protocols
outbound_list = ["freedom", "blackhole", "both"]

# link schematic
vmess_scheme = "vmess://"
shadowsocks_scheme = "ss://"

# TROJAN PASSWORD
trojanpassword = None

# Docker Compose Version
DOCKERCOMPOSEVERSION = docker_compose_version()

# Supported XRay Configuration Protocols
supported_typo = [
    "vmessws",
    "vmesswstls",
    "vmesstcp",
    "vmesstcptls",
    "vlesswstls",
    "vlesstcptls",
    "vlesstcpxtls",
    "shadowsockstcp",
    "shadowsockstcptls",
    "trojanwstls",
    "trojantcptls",
    "trojantcpxtls",
]


def protocol_map():
    """
    Map user-entered arguments to supported protocols.
    If unsupported protocols are entered, raise an exception with a list of available protocols,
    prioritizing arguments with more parameters.
    """
    # vmesstcptls
    if all((args.vmess, args.tcp, args.tls)):
        protocol_type = supported_typo[3]
    # trojantcptls
    elif all((args.trojan, args.tcp, args.tls)):
        protocol_type = supported_typo[10]
    # trojantcpxtls
    elif all((args.trojan, args.tcp, args.xtls)):
        protocol_type = supported_typo[11]
    # vlesstcpxtls
    elif all((args.vless, args.tcp, args.xtls)):
        protocol_type = supported_typo[6]
    # vmesstcp
    elif all((args.vmess, args.tcp)):
        protocol_type = supported_typo[2]
    # trojantcptls
    elif all((args.trojan, args.tcp)):
        protocol_type = supported_typo[10]
    # trojantcpxtls
    elif all((args.trojan, args.xtls)):
        protocol_type = supported_typo[11]
    # vlesstcpxtls
    elif all((args.vless, args.xtls)):
        protocol_type = supported_typo[6]
    # vlesstcptls
    elif all((args.vless, args.tcp)):
        protocol_type = supported_typo[5]
    # shadowsockstcptls
    elif all((args.shadowsocks, args.tls)):
        protocol_type = supported_typo[8]
    # vmesswstls
    elif all((args.vmess, args.tls)):
        protocol_type = supported_typo[1]
    # shadowsockstcp
    elif args.shadowsocks:
        protocol_type = supported_typo[7]
    # vmessws
    elif args.vmess:
        protocol_type = supported_typo[0]
    # vlesswstls
    elif args.vless:
        protocol_type = supported_typo[4]
    # trojanwstls
    elif args.trojan:
        protocol_type = supported_typo[9]
    else:
        raise Exception("Unsupported Protocol.\n{}".format(protocols_list()))
    return protocol_type


def protocols_list() -> None:
    print("LIST OF SUPPORTED PROTOCOLS")
    print("Protocols like VLess or Trojan require TLS by default.")
    params = {
        "VMESS WS": "--vmess",
        "VMESS WS TLS": "--vmess --tls",
        "VMESS TCP": "--vmess --tcp",
        "VMESS TCP TLS": "--vmess --tcp --tls",
        "VLESS WS TLS": "--vless",
        "VLESS TCP TLS": "--vless --tcp",
        "VLESS TCP XTLS": "--vless --tcp --xtls",
        "TROJAN WS TLS": "--trojan",
        "TROJAN TCP TLS": "--trojan --tcp",
        "TROJAN TCP XTLS": "--trojan --tcp",
        "ShadowSocks TCP": "--shadowsocks",
        "ShadowSocks TCP TLS": "--shadowsocks --tls",
    }
    for protocols, parameters in params.items():
        print(green + protocols + reset, ":", yellow + parameters + reset)


# -------------------------------- VMess JSON --------------------------------- #


def xray_make():
    """
    Make JSON config which reads --outband for making v2ray vmess config with specific protocol
    https://www.v2ray.com/en/configuration/protocols/v2ray.html
    """
    global proto_name
    # Config Protocol Method
    if proto_type == "vmessws":
        proto_name = "VMESS + WS"

    elif proto_type == "vmesswstls":
        proto_name = "VMESS + WS + TLS"

    elif proto_type == "vmesstcp":
        proto_name = "VMESS + TCP"

    elif proto_type == "vmesstcptls":
        proto_name = "VMESS + TCP + TLS"

    elif proto_type == "vlesswstls":
        proto_name = "VLESS + WS + TLS"

    elif proto_type == "vlesstcptls":
        proto_name = "VLESS + TCP + TLS"

    elif proto_type == "vlesstcpxtls":
        proto_name = "VLESS + TCP + XTLS"

    elif proto_type == "trojanwstls":
        proto_name = "TROJAN + WS + TLS"

    elif proto_type == "trojantcptls":
        proto_name = "TROJAN + TCP + TLS"

    elif proto_type == "trojantcpxtls":
        proto_name = "TROJAN + TCP + XTLS"

    elif proto_type == "shadowsockstcp":
        proto_name = "SHADOWSOCKS + TCP"

    elif proto_type == "shadowsockstcptls":
        proto_name = "SHADOWSOCKS + TCP + TLS"

    if proto_type.startswith("vmess"):
        make_xray("vmess")
    elif proto_type.startswith("vless"):
        make_xray("vless")
    elif proto_type.startswith("trojan"):
        make_xray("trojan")
    elif proto_type.startswith("shadowsocks"):
        make_xray("shadowsocks")

    print(
        "{}! {}{}{}{} Config Generated.{}".format(
            blue, green, proto_name, reset, blue, reset
        )
    )
    if args.vless or args.trojan:
        print(
            "{}! By default TLS is being used for this Protocol{}".format(yellow, reset)
        )


def xray_config(outband, protocol) -> str:
    """
    Xray JSON config file template
    """
    global NETSTREAM

    if args.xtls:
        print(
            "{}! XTLS only supports (TCP,mKCP). Using TCP mode{}".format(yellow, reset)
        )

    if args.tls:
        tls_config = tlssettings()
    elif args.vless:
        tls_config = tlssettings()
    elif args.trojan:
        tls_config = tlssettings()
    else:
        tls_config = notls()

    if args.tcp or args.shadowsocks or args.xtls:
        networkstream = tcp()
        NETSTREAM = "TCP"
    else:
        networkstream = websocket_config(args.wspath)
        NETSTREAM = "WebSocket"

    if args.block or args.blockir:
        routing_config = routing() + ","
        sniffing_config = sniffing() + ","
    else:
        routing_config = ""
        sniffing_config = ""

    if args.tcp or args.shadowsocks or args.xtls:
        # TCP stream settings
        streamsettings = """
        "streamSettings": {
					   
        %s,
        %s,
        "tcpSettings": %s
        }        
        """ % (
            networkstream,
            tls_config,
            args.header,
        )

    else:
        # Normal stream settings
        streamsettings = """
        "streamSettings":{ 
        %s,            
        %s,
        "headersettings": %s 
        }        
        """ % (
            networkstream,
            tls_config,
            args.header,
        )

    data = """{
    %s
    %s,
    %s
  "inbounds": [
    {
        %s
        "port": %s,
        %s,
        %s
    }
  ],
  "outbounds": [
    %s
  ]
}""" % (
        DNS,
        log(),
        routing_config,
        sniffing_config,
        PORT,
        protocol,
        streamsettings,
        outband,
    )

    return json.loads(data)


# -------------------------------- Xray Config --------------------------------- #


def make_xray(protocol):
    """
    make xray config based on selected protocol
    """

    outband_config = outband()
    protocol_config = ""
    if protocol == "vless":
        protocol_config = vless_server_side()
    elif protocol == "vmess":
        protocol_config = vmess_server_side()
    elif protocol == "trojan":
        protocol_config = trojan_server_side()
    elif protocol == "shadowsocks":
        protocol_config = shadowsocks_server_side()

    # Config Protocol Method
    with open(CONFIGNAME, "w") as txt:
        txt.write(
            json.dumps(
                xray_config(outband_config, protocol_config),
                indent=2,
            )
        )
        txt.close


def outband():
    return freedom() + ",\n" + blackhole()


# -------------------------------- JSON Configuration --------------------------------- #


def vmess_server_side():
    """
    vmess server side inbound configuration
    https://xtls.github.io/config/inbounds/vmess.html
    """
    vmess = """
        "protocol": "vmess",
        "allocate": {
          "strategy": "always"
        },
        "settings": {
          "clients": [
            {
              "id": "%s",
              "level": 1,
              "alterId": %s,
              "email": "client@example.com"
            }
          ],
          "disableInsecureEncryption": %s
        }""" % (
        UUID,
        args.alterid,
        args.insecure,
    )
    return vmess


def trojan_server_side():
    """
    vless server side inbound configuration
    https://xtls.github.io/config/inbounds/vless.html
    """
    trojan = """
      "protocol": "trojan",
      "allocate": {
        "strategy": "always"
      },    
      "settings": {
        "clients": [
          {
            "password": "%s",
            "email": "client@example.com"
          }
        ]
        }""" % (
        trojanpassword
    )
    return trojan


def vless_server_side():
    """
    vless server side inbound configuration
    https://xtls.github.io/config/inbounds/vless.html
    """
    vless = """
      "protocol": "vless",
      "settings": {
      "clients": [
        {
          "id": "%s",
          "level": 0,
          "email": "client@example.com"
        }
      ],
      "decryption": "none"
  }""" % (
        UUID
    )
    return vless


def shadowsocks_server_side():
    """
    shadowsocks server side inbound configuration
    https://xtls.github.io/config/outbounds/shadowsocks.html
    """
    shadowsocks = """
        "protocol": "shadowsocks",
        "settings": {
          "method": "%s",
          "password": "%s"
        }""" % (
        args.ssmethod,
        args.sspass,
    )
    return shadowsocks


def block_torrent_manually():
    iptables_cmds = [
        "iptables -A FORWARD -s 10.8.1.0/24 -p tcp --dport 443 -j DROP",
        "iptables -A FORWARD -i tun+ -j ACCEPT",
        'iptables -A INPUT -m string --string "BitTorrent" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "BitTorrent protocol" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "peer_id=" --algo bm -j DROP',
        'iptables -A INPUT -m string --string ".torrent" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "announce.php?passkey=" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "torrent" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "announce" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "info_hash" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "tracker" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "get_peers" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "announce_peer" --algo bm -j DROP',
        'iptables -A INPUT -m string --string "find_node" --algo bm -j DROP',
    ]
    for cmd in iptables_cmds:
        subprocess.run(cmd, shell=True, check=True)


def routing() -> str:
    if args.block:
        return block_adds_bittorent()

    if args.blockir:
        return block_adds_bittorent_ir()


def block_adds_bittorent() -> str:
    """
    routing configuration for block bittorrent and private ip addresses.
    https://guide.v2fly.org/en_US/routing/bittorrent.html#server-side-configuration
    """
    data = """
    "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "protocol": ["bittorrent"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": ["geosite:category-ads-all"],
        "outboundTag": "block"
      }
    ]
  }"""
    return data


def block_adds_bittorent_ir() -> str:
    """
    routing configuration for block bittorrent and private ip addresses.
    https://guide.v2fly.org/en_US/routing/bittorrent.html#server-side-configuration
    """

    # ips_file_url = (
    #     "https://raw.githubusercontent.com/SonyaCore/V2RayGen/main/IranIPs.txt"
    # )
    # irips = urlopen(ips_file_url).read().decode("utf-8")

    url = Request("https://cdn-lite.ip2location.com/datasets/IR.json")

    with urlopen(url) as respone:
        data = respone.read()

    dat = json.loads(data)

    path = "/tmp/dump"
    cidrs = []
    for item in dat["data"]:
        start = ipaddress.IPv4Address(item[:2][0])
        end = ipaddress.IPv4Address(item[:2][1])
        cidrs.append(next(ipaddress.summarize_address_range(start, end)))

    for v, datasets in enumerate(cidrs):
        with open(path, "a") as file:
            file.write(str('"') + str(datasets) + str('"'))
            if v != len(cidrs) - 1:
                file.write(str(","))
            file.write("\n")

    irips = open(path, "r").read()
    os.remove(path)

    data = """
    "routing": {
    "domainStrategy": "IPIfNonMatch",
    "domainMatcher": "hybrid",
    "rules": [
      {
        "type": "field",
        "protocol": ["bittorrent"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "ip": [
            "geoip:private",
			%s
        ],
        "outboundTag": "block"
      },
      {        
        "type": "field",
        "domain": [
            "geosite:category-ads-all",
			"regexp:.ir$",
            "regexp:digikala.com$"
        ],
        "outboundTag": "block"
      }
    ]
  }""" % (
        irips
    )
    return data


def sniffing() -> str:
    """
    sniffing must be turned on for routing option.
    """
    data = """
        "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    """
    return data


def tlssettings() -> str:
    """
    tls security settings for protocols with tls
    """
    if args.xtls:
        server_security = "xtls"
        tls_server_type = "xtlsSettings"
    else:
        server_security = "tls"
        tls_server_type = "tlsSettings"

    tls = """
    "security": "%s",    
    "%s": {
          "alpn": ["http/1.1"],
          "certificates": [
            {
              "certificateFile": "%s",
              "keyFile": "%s"
            }
          ]
        }""" % (
        server_security,
        tls_server_type,
        crtkey,
        hostkey,
    )
    return tls


def notls() -> str:
    """
    no tls for protocols without tls
    """
    notls = """
    "security": "none"
    """
    return notls


def websocket_config(path) -> str:
    """
    WebSocket stream setting template for JSON.
    by default, WebSocket is used for transporting data.
    Websocket connections can be proxied by HTTP servers such as Nginx.
    https://www.v2ray.com/en/configuration/transport/websocket.html
    """
    if not path:
        path = "/graphql"

    websocket = """
          "network": "ws",
          "wsSettings": {
            "connectionReuse": true,
            "path": "%s"
          } 
    """ % (
        path
    )
    return websocket


# def http() -> str:
#     """
#     Http Network setting template for JSON.
#     """
#     http = """
#         "network": "http"
#         """
#     return http


def tcp() -> str:
    """
    Http Network setting template for JSON.
    """
    tcp = """
        "network": "tcp"
         """
    return tcp


def freedom() -> str:
    """
    Freedom protocol template JSON config.
    adding freedom outbound to json config
    It passes all TCP or UDP connection to their destinations.
    This outbound is used when you want to send traffic to its real destination.
    it can be used as a single outbound connection witch default --vmess arg uses.
    https://www.v2ray.com/en/configuration/protocols/freedom.html
    """

    freedom = """ {
      "protocol": "freedom",
      "settings": {}
    }"""

    return freedom


def blackhole() -> str:
    """
    Blackhole protocol template JSON config.
    with this fucntion blackhole outbound will be added in json
    it can be combined with freedom or as a single outbound connection
    https://www.v2ray.com/en/configuration/protocols/blackhole.html
    """

    blackhole = """ {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }"""
    return blackhole


def headersettings(direction) -> str:
    """
    default tcp setting header for json configuration.
    for using custom configuration use ( --header file.json ) option to configure your own header
    """

    request = """ 
    "request": {
        "version": "1.1",
        "method": "GET",
        "headers": {
          "Host": [
            "www.google.com", 
            "www.bing.com",
            "www.msn.com",
            "www.yahoo.com",
            "www.hotmail.com",
            "outlook.live.com",
            "www.microsoft.com",
            "mail.google.com",
            "www.proton.me"
          ],
          "User-Agent": [
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"            
          ],
          "Accept-Encoding": [
                "gzip, deflate",
                "compress, deflate",
                "gzip, compress",
                "identity, deflate",
                "compress, identity",
                "gzip, identity"
            ],
          "Connection": ["keep-alive"],
          "Pragma": "no-cache"
        }
      }
        """

    response = """ 
    "request": {
        "version": "1.1",
        "status": "200",
        "reason": "OK",
        "headers": {
            "Content-Type": [
                "application/pdf",
                "application/xhtml+xml",
                "application/x-shockwave-flash",
                "application/json",
                "application/ld+json",
                "application/xml",
                "application/zip",
                "application/x-www-form-urlencoded",
                "image/gif",
                "image/jpeg",
                "image/png",
                "image/tiff",
                "image/vnd.microsoft.icon",
                "image/x-icon",
                "image/vnd.djvu",
                "image/svg+xml",
                "multipart/mixed",
                "multipart/alternative",
                "multipart/related",
                "multipart/form-data",
                "text/css",
                "text/csv",
                "text/html",
                "text/plain",
                "text/xml"
            ],
            "Transfer-Encoding": ["chunked"],
            "Connection": ["keep-alive"],
            "Pragma": "no-cache"
        }
      }
        """

    header = """
    {
        "header": {
              "type": "http",
              %s
            }
    }
    """ % (
        response if direction == "in" else request
    )

    return header


def log():
    log = """
    "log": {
    "loglevel": "%s"
  }""" % (
        LOG
    )
    return log


def loglevel():
    """
    loglevel are for changing Server-side loglevel
    https://guide.v2fly.org/en_US/basics/log.html#server-side-configuration
    """
    global LOG

    # list of loglevels
    loglevel = ["debug", "info", "warning", "error", "none"]
    loglevel_messages = [
        'Information for developers. All "Info" included.',
        'Running stats of XRay，no effect for the functions. All "Warning" included.',
        "usually some external problem that does not affect V2Ray but possibly the user experience.",
        "XRay encountered a problem that needs to be resolved immediately.",
        "Nothing will be printed.",
    ]
    cmd = args.loglevel.lower()

    # checking loglevel argument
    if cmd == "debug":
        LOG = loglevel[0]
    if cmd == "info":
        LOG = loglevel[1]
    if cmd == "warning":
        LOG = loglevel[2]
    if cmd == "error":
        LOG = loglevel[3]
    if cmd == "none":
        LOG = loglevel[4]

    # printing list of log levels if user input is not in loglevels
    if cmd not in loglevel:
        print("list of loglevels :")
        for levels in range(len(loglevel)):
            print(green + loglevel[levels] + " : " + loglevel_messages[levels] + reset)
        sys.exit()


def client_security():
    """
    client_security are for changing Client-side Security method
    https://www.v2ray.com/en/configuration/protocols/v2ray.html#userobject
    """
    global SECURITY

    # list of loglevels
    security_methods = ["aes-128-gcm", "chacha20-poly1305", "auto", "none", "zero"]

    cmd = args.security.lower()

    # checking loglevel argument
    if cmd == "aes-128-gcm":
        SECURITY = security_methods[0]
    if cmd == "chacha20-poly1305":
        SECURITY = security_methods[1]
    if cmd == "auto":
        SECURITY = security_methods[2]
    if cmd == "none":
        SECURITY = security_methods[3]
    if cmd == "zero":
        SECURITY = security_methods[4]

    # printing list of security methods if user input is not in security_methods var.
    if cmd not in security_methods:
        print("list of security methods :")
        for methods in range(len(security_methods)):
            print(green + security_methods[methods] + reset)
        sys.exit()


# -------------------------------- Client Side Configuration --------------------------------- #


def client_side_configuration(protocol):
    """
    client side configuration for generating client side json configuration.
    it can be used as configuration file for xray-core.
    """
    vmess_client = """
        "protocol": "vmess",
        "settings": {
            "vnext": [
            {
                "address": "%s",
                "port": %s,
                "users": [
                {
                    "alterId": %s,
                    "id": "%s",
                    "security": "%s"
                }
                ]
            }
            ]
        }""" % (
        ServerIP,
        PORT,
        args.alterid,
        UUID,
        SECURITY,
    )

    vless_clinet = """
        "protocol": "vless",
        "settings": {
        "vnext": [
        {
            "address": "%s",
            "port": %s,
            "users": [
            {
                "encryption": "none",
                "id": "%s"
            }
            ]
        }
        ]
    }""" % (
        ServerIP,
        PORT,
        UUID,
    )

    trojan_client = """
        "protocol": "trojan",
        "settings": {
        "servers": [
            {
                "address": "%s",
                "port": %s,
                "password": "%s"
                }
            ]
        }
    """ % (
        ServerIP,
        PORT,
        trojanpassword,
    )

    shadowsocks_clinet = """
        "protocol": "shadowsocks",
        "settings": {
        "servers": [
          {
            "address": "%s",
            "port": %s,
            "method": "%s",
            "password": "%s"
          }
        ]
    }""" % (
        ServerIP,
        PORT,
        args.ssmethod,
        args.sspass,
    )

    # client protocol settings based on protocol argument
    if protocol == "VMESS":
        setting = vmess_client
    elif protocol == "VLESS":
        setting = vless_clinet
    elif protocol == "TROJAN":
        setting = trojan_client
    elif protocol == "SHADOWSOCKS":
        setting = shadowsocks_clinet

    inbounds = """
        "inbounds": [
        {
            "tag": "socks-in",
            "port": %s,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": true
            }       
        },
        {
            "tag": "http-in",
            "port": %s,
            "listen": "127.0.0.1",       
            "protocol": "http",
            "settings": {
                "auth": "noauth",
                "udp": true
            }
        }
    ]""" % (
        SOCKSPORT,
        HTTPPORT,
    )

    if args.xtls:
        tls_client_type = "xtlsSettings"
        security = "xtls"
    else:
        tls_client_type = "tlsSettings"
        security = "tls"

    tls_client = """
        "security": "%s",
        "%s": {
          "allowInsecure": true,
          "alpn": [
            "http/1.1"
          ],
          "fingerprint": ""
        }
        """ % (
        security,
        tls_client_type,
    )

    if args.tcp or args.shadowsocks or args.xtls:
        network = "tcp"
    else:
        network = "websocket"

    wsSettings = """
        "wsSettings": { "path": "%s" }
        """ % (
        args.wspath
    )

    streamsettings_client = """
        "streamSettings": {
        "network": "%s",
        %s
        %s
        %s
      },
      "tag": "proxy"
    """ % (
        network,
        tls_client if proto_type.__contains__("tls") else notls(),
        ',"tcpSettings":' + headersettings("out")
        if proto_type.__contains__("tcp")
        else "",
        "," + wsSettings if not args.tcp and not args.shadowsocks else "",
    )

    outbands_client = """
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "freedom", "tag": "bypass" },
    { "protocol": "blackhole", "tag": "block" }
    """

    #    policy = """
    #    "policy": {
    #    "levels": { "1": { "connIdle": 30 } },
    #    "system": { "statsOutboundDownlink": true, "statsOutboundUplink": true }
    #  }"""

    outbands = """
    "outbounds": [
    {
      %s,
      %s,
      "mux": {
        "enabled": false,
        "concurrency": -1
      }
    },
    %s    
  ]
    """ % (
        setting,
        streamsettings_client,
        outbands_client,
    )

    #   {
    #     "protocol": "dns",
    #     "proxySettings": { "tag": "proxy", "transportLayer": true },
    #     "settings": {
    #       "address": "8.8.8.8",
    #       "network": "tcp",
    #       "port": 53,
    #       "userLevel": 1
    #     },
    #     "tag": "dns-out"
    #   }

    client_configuration = """
    {
        "log": { "loglevel": "%s" },
        %s,        
        %s
    }
    """ % (
        LOG,
        inbounds,
        outbands,
    )

    jsondata = json.loads(client_configuration)
    client_configuration_name = "client-{}-{}.json".format(
        proto_name.replace(" + ", "-"), args.linkname
    )
    with open(client_configuration_name, "w") as wb:
        wb.write(json.dumps(jsondata, indent=2))
        wb.close

    print("")
    filename = green + client_configuration_name + reset
    print(
        blue
        + "! Client-side {} Config Generated.".format(proto_name.replace(" + ", "-")),
        reset,
    )
    print(
        "{}! Use {}{} for using proxy with xray-core directly.{}".format(
            blue, filename, blue, reset
        )
    )
    print(
        blue
        + "! Or use below one-line compact json Client-Side and import it directly in your client:",
        reset,
    )
    print(
        green + json.dumps(jsondata, separators=(",", ":")),
        reset,
    )
    print("")
    print("")


# -------------------------------- Config Creation --------------------------------- #


def xray_create(protocol):
    dnsselect()

    # Making xray / v2ray configuration file
    xray_make()
    sys.exit(1) if args.config else ""

    if args.tls or args.vless or args.trojan:
        create_key()
        time.sleep(0.5)

    if args.tls or args.vless or args.trojan:
        print(
            yellow
            + "! Using self-signed key\
        \n! Make sure to add Allow Insecure to your client."
            + reset
        )

    if args.tcp:
        print(
            yellow
            + "! For using TCP in your gui client set header to 'http' and 'path' to '/' "
        )

    # Creating docker-compose file
    xray_dockercompose()

    # Running docker-compose on Server
    run_docker()

    # Printing Information
    serverside_info_raw()

    # Generate encoded link & client-side configuration
    if protocol == "VMESS":
        vmess_link = vmess_link_generator(
            args.alterid, UUID, net, path, PORT, args.linkname, TLSTYPE, header
        )
        print(vmess_link)

        if args.qrcode:
            print(yellow + "! QRCode :" + reset)
            print(qrcode(vmess_link))

        if protocol == "VMESS":
            client_side_configuration("VMESS")

    elif protocol == "VLESS":
        vless_link = vless_link_generator(UUID, PORT, net, path, TLSTYPE, args.linkname)
        print(vless_link)

        if args.qrcode:
            print(yellow + "! QRCode :" + reset)
            print(qrcode(vless_link))
        client_side_configuration("VLESS")

    elif protocol == "TROJAN":
        trojan_link = trojan_link_generator(
            trojanpassword, PORT, TLSTYPE, net, path, args.linkname
        )
        print(trojan_link)

        if args.qrcode:
            print(yellow + "! QRCode :" + reset)
            print(qrcode(trojan_link))
        client_side_configuration("TROJAN")

    elif protocol == "SHADOWSOCKS":
        shadowsocks_link = shadowsocks_link_generator()
        print(shadowsocks_link)

        if args.qrcode:
            print(yellow + "! QRCode :" + reset)
        client_side_configuration("SHADOWSOCKS")

    # Generate NGINX Template
    country() if protocol == "VMESS" else None


# -------------------------------- Parse URL --------------------------------- #


def parseLink(link):
    if link.startswith(vmess_scheme):
        print(parse_VMess(link))
    elif link.startswith(shadowsocks_scheme):
        print(parse_ShadowSocks(link))
    else:
        links = vmess_scheme, shadowsocks_scheme
        print(
            "{}ERROR:{} --parse arg supports only {} {} {} links".format(
                error, reset, green, links, reset
            )
        )
        sys.exit(1)


def parse_ShadowSocks(sslink):
    """
    Parse Shadowsocks encoded link into a dictionary list.
    """
    SHADOWSS = {
        "v": "2",
        "ps": "",
        "add": "",
        "port": "",
        "id": "",
        "aid": "",
        "net": "shadowsocks",
        "type": "",
        "host": "",
        "path": "",
        "tls": "",
    }
    try:
        if sslink.startswith(shadowsocks_scheme):
            info = sslink[len(shadowsocks_scheme) :]

            if info.rfind("#") > 0:
                info, ps = info.split("#", 2)
                SHADOWSS["ps"] = unquote(ps)

            if info.find("@") < 0:
                blen = len(info)
                if blen % 4 > 0:
                    info += "=" * (4 - blen % 4)

                info = base64.b64decode(info).decode()

                atidx = info.rfind("@")
                method, password = info[:atidx].split(":", 2)
                addr, port = info[atidx + 1 :].split(":", 2)
            else:
                atidx = info.rfind("@")
                addr, port = info[atidx + 1 :].split(":", 2)

                info = info[:atidx]
                blen = len(info)
                if blen % 4 > 0:
                    info += "=" * (4 - blen % 4)

                info = base64.b64decode(info).decode()
                method, password = info.split(":", 2)

            SHADOWSS["add"] = addr
            SHADOWSS["port"] = port
            SHADOWSS["aid"] = method
            SHADOWSS["id"] = password
            return yellow + str(SHADOWSS) + reset
    except ValueError as err:
        sys.exit(error + "Invalid ShadowSocks Link : " + reset + str(err))


def parse_VMess(vmesslink):
    """
    Parse VMess encoded link into a dictionary list.
    """
    try:
        if vmesslink.startswith(vmess_scheme):
            link = vmesslink[len(vmess_scheme) :]
            bytelen = len(link)
            if bytelen % 4 > 0:
                link += "=" * (4 - bytelen % 4)

            vms = base64.b64decode(link).decode()

            return yellow + str(json.loads(vms)) + reset
        else:
            raise Exception("vmess link invalid")
    except json.decoder.JSONDecodeError as err:
        sys.exit(error + "Invalid VMess link : " + reset + str(err))
    except Error as err:
        sys.exit(error + "Invalid Format : " + reset + str(err))


# -------------------------------- Docker --------------------------------- #


def xray_dockercompose():
    """
    Create docker-compose file for xray-core.
    in this docker-compose xray-core is being used for running xray in the container.
    https://hub.docker.com/r/teddysun/xray
    """
    if args.v2ray:
        type = "v2ray"
    else:
        type = "xray"

    docker_crtkey = "- ./{}:/etc/{}/{}:ro".format(
        SELFSIGEND_CERT, type, SELFSIGEND_CERT
    )
    docker_hostkey = "- ./{}:/etc/{}/{}:ro".format(SELFSIGEND_KEY, type, SELFSIGEND_KEY)

    if args.v2ray:
        data = """version: '3'
services:
  v2ray:
    image: v2fly/v2fly-core
    restart: always
    network_mode: host
    environment:
      - V2RAY_VMESS_AEAD_FORCED=false
    entrypoint: ["v2ray", "run", "-c", "/etc/v2ray/config.json"]
    volumes:
        - ./%s:/etc/v2ray/config.json:ro
        %s
        %s""" % (
            CONFIGNAME,
            docker_crtkey if proto_type.__contains__("tls") or args.tls else "",
            docker_hostkey if proto_type.__contains__("tls") or args.tls else "",
        )
    else:
        data = """version: '3'
services:
  xray:
    image: teddysun/xray
    restart: always
    network_mode: host
    environment:
      - V2RAY_VMESS_AEAD_FORCED=false
    entrypoint: ["/usr/bin/xray", "-config", "/etc/xray/config.json"]
    volumes:
        - ./%s:/etc/xray/config.json:ro
        %s
        %s""" % (
            CONFIGNAME,
            docker_crtkey if proto_type.__contains__("tls") or args.tls else "",
            docker_hostkey if proto_type.__contains__("tls") or args.tls else "",
        )

    print(
        yellow
        + "! Created {}-core {} configuration".format(type, DOCKERCOMPOSE)
        + reset
    )
    with open(DOCKERCOMPOSE, "w") as txt:
        txt.write(data)
        txt.close()


def run_docker():
    """
    Start xray docker-compose.
    at first, it will check if docker exists and then check if docker-compose exists
    if docker is not in the path it will install docker with the official script.
    then it checks the docker-compose path if the condition is True docker-compose.yml will be used for running xray.
    """
    try:
        # Check if docker exist
        if os.path.exists("/usr/bin/docker") or os.path.exists("/usr/local/bin/docker"):
            pass
        else:
            # Install docker if docker are not installed
            try:
                print(yellow + "Docker Not Found.\nInstalling Docker ...")
                subprocess.run(
                    "curl https://get.docker.com | sh", shell=True, check=True
                )
            except subprocess.CalledProcessError:
                sys.exit(error + "Download Failed !" + reset)

        # Check if Docker Service are Enabled
        systemctl = subprocess.call(["systemctl", "is-active", "--quiet", "docker"])
        if systemctl == 0:
            pass
        else:
            subprocess.call(["systemctl", "enable", "--now", "--quiet", "docker"])

        time.sleep(2)

        # Check if docker-compose exist
        if os.path.exists("/usr/bin/docker-compose") or os.path.exists(
            "/usr/local/bin/docker-compose"
        ):
            subprocess.run(
                "docker-compose -f {} up -d".format(DOCKERCOMPOSE),
                shell=True,
                check=True,
            )
            reset_docker_compose()
        else:
            print(
                yellow
                + "docker-compose Not Found.\nInstalling docker-compose {} ...".format(
                    DOCKERCOMPOSEVERSION
                )
            )
            subprocess.run(
                "curl -SL https://github.com/docker/compose/releases/download/{}/docker-compose-linux-x86_64 \
        -o /usr/local/bin/docker-compose".format(
                    DOCKERCOMPOSEVERSION
                ),
                shell=True,
                check=True,
            )
            subprocess.run(
                "chmod +x /usr/local/bin/docker-compose", shell=True, check=True
            )
            subprocess.run(
                "ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose",
                shell=True,
                check=True,
            )

            subprocess.run(
                "docker-compose -f {} up -d".format(DOCKERCOMPOSE),
                shell=True,
                check=True,
            )
    except subprocess.CalledProcessError as e:
        sys.exit(error + str(e) + reset)
    except PermissionError:
        sys.exit(error + "ًroot privileges required" + reset)


def reset_docker_compose():
    subprocess.run("docker-compose restart", shell=True, check=True)


# ------------------------------ Firewall ------------------------------- #


def firewall_config():
    """
    add configuration port to firewall.
    by default, it checks if the ufw or firewalld exists and adds the rule to the firewall
    else iptables firewall rule will be added
    """
    try:
        if os.path.exists("/usr/sbin/ufw"):
            service = "ufw"
            subprocess.run("ufw allow {}".format(PORT), check=True, shell=True)
        elif os.path.exists("/usr/sbin/firewalld"):
            service = "firewalld"
            subprocess.run(
                "firewall-cmd --permanent --add-port={}/tcp".format(PORT),
                shell=True,
                check=True,
            )
        else:
            service = "iptables"
            subprocess.run(
                "iptables -t filter -A INPUT -p tcp --dport {} -j ACCEPT".format(PORT),
                shell=True,
                check=True,
            )
            subprocess.run(
                "iptables -t filter -A OUTPUT -p tcp --dport {} -j ACCEPT".format(PORT),
                shell=True,
                check=True,
            )
        print(green + "Added " + str(PORT) + " " + "to " + service + reset)
    except subprocess.CalledProcessError as e:
        sys.exit(error + str(e) + reset)


# ------------------------------ Configuration Info ------------------------------- #


def serverside_info_raw() -> str:
    """
    show generated configuration info
    """
    if args.trojan:
        method = "PASSWORD"
        value = trojanpassword
    else:
        method = "UUID"
        value = UUID

    print("")
    print("SERVER SIDE Information : ")
    print("IP: " + blue + str((ServerIP)) + reset)
    print("ID: " + blue + str(args.alterid) + reset)
    print("LOGLEVEL: " + blue + str(LOG) + reset)
    print("{}: ".format(method) + blue + str(value) + reset)
    print("STREAM : " + blue + str(NETSTREAM) + reset)

    if NETSTREAM == "WebSocket":
        print("WSPATH: " + blue + str(args.wspath) + reset)

    print("PORT: " + blue + str(PORT) + reset)
    print("SECURITY: " + blue + str(TLSTYPE) + reset)
    print("LINKNAME: " + blue + str(args.linkname) + reset)

    if args.csocks or args.chttp:
        print("")
        print("CLIENT SIDE Information : ")
        print("SECURITY : " + blue + str(SECURITY) + reset)
        print("HTTP PORT : " + blue + str(HTTPPORT) + reset)
        print("SOCKS PORT : " + blue + str(SOCKSPORT) + reset)


def read_serverside_configuration(config):
    """
    parse server-side configuration file
    https://www.v2ray.com/en/configuration/overview.html
    """
    global ID, AlterId, net, path, configport, securitymethod, protocol

    with open(config, "r") as configfile:
        data = json.loads(configfile.read())

    try:
        # essential info that must be in the json configuration file
        ID = data["inbounds"][0]["settings"]["clients"][0]["id"]
        protocol = data["inbounds"][0]["protocol"]
        configport = data["inbounds"][0]["port"]
        try:
            if data["inbounds"][0]["streamSettings"]["network"] == "tcp":
                securitymethod = data["inbounds"][0]["streamSettings"]["security"]
            else:
                securitymethod = data["inbounds"][0]["security"]
        except KeyError:
            securitymethod = "none"
            pass

        print(yellow + "Inbounds Info:" + reset)
        try:
            configloglevel = data["log"]["loglevel"]
            print(blue + "Loglevel : " + reset + str(configloglevel))
        except KeyError:
            pass

        print(blue + "PROTOCOL : " + reset + str(protocol))
        print(blue + "PORT : " + reset + str(configport))
        print("")
        print(yellow + "Client Info:" + reset)
        print(blue + "ID : " + reset + str(ID))

        try:
            clientlevel = data["inbounds"][0]["settings"]["clients"][0]["level"]
            print(blue + "Level : " + reset + str(clientlevel))
        except KeyError:
            pass

        try:
            AlterId = data["inbounds"][0]["settings"]["clients"][0]["alterId"]
            if AlterId != None:
                print(blue + "alterId : " + reset + str(AlterId))
            else:
                pass
        except KeyError:
            AlterId = 0
            pass

        print("")
        print(yellow + "Stream Settings:" + reset)
        try:
            net = data["inbounds"][0]["streamSettings"]["network"]
            print(blue + "Network : " + reset + str(net))
        except KeyError:
            net = ""
            pass

        try:
            if data["inbounds"][0]["streamSettings"]["network"] == "ws":
                try:
                    path = data["inbounds"][0]["streamSettings"]["wsSettings"]["path"]
                    print(blue + "WebSocket Path : " + reset + str(path))
                except KeyError:
                    path = ""
                    pass
        except KeyError:
            pass

        print(blue + "Security : " + reset + str(securitymethod))

        try:
            outbands = []
            for each in data["outbounds"]:
                outbands.append(each["protocol"])
            print(blue + "OutBounds : " + reset + str(outbands))
        except KeyError:
            outbands = None
            pass

        print(blue + "Link : " + reset + str(link_serverside_configuration()))
        print(blue + "QRCode : \n" + reset + qrcode(link_serverside_configuration()))

    except KeyError as e:
        sys.exit(error + "ERROR: " + str(e) + " not found in {}!".format(config))


def link_serverside_configuration():
    """
    generate link with server-side configuration file.
    """

    if protocol == "vmess":
        return vmess_link_generator(
            AlterId, ID, net, path, configport, linkname, securitymethod, header
        )
    elif protocol == "vless":
        return vless_link_generator(ID, configport, net, path, securitymethod, linkname)


# ------------------------------ VMess Link Gen ------------------------------- #


def vmess_link_generator(aid, id, net, path, port, ps, tls, header) -> str:
    """
    Generate vmess link.
    vmess link is being used for importing v2ray config in clients.
    vmess links are encoded with base64.
    """

    if not args.parseconfig:
        print("")
        print(yellow + "! Use below link for your xray or v2ray client" + reset)

    prelink = "vmess://"
    raw_link = bytes(
        "{"
        + """"add":"{}",\
"aid":"{}",\
"host":"",\
"id":"{}",\
"net":"{}",\
"path":"{}",\
"port":"{}",\
"ps":"{}",\
"tls":"{}",\
"type":"{}",\
"v":"2" """.format(
            ServerIP, aid, id, net, path, port, ps, tls, header
        )
        + "}",
        encoding="ascii",
    )

    link = base64.b64encode(raw_link)  # encode raw link

    vmess_link = prelink + str(link.decode("utf-8"))  # concatenate prelink with rawlink

    return vmess_link


# ------------------------------ VLess Link Gen ------------------------------- #


def vless_link_generator(id, port, net, path, security, name) -> str:
    """
    generate vless link with below format:
    vless://id@IP:PORT?path&security&encryption&type#linkname
    """
    if not args.parseconfig:
        print("")
        print(yellow + "! Use below link for your xray or v2ray client" + reset)

    prelink = "vless://"
    raw_link = "{}@{}:{}?path={}&security={}&encryption=none&type={}#{}".format(
        id, ServerIP, port, path, security, net, name
    )

    vless_link = prelink + raw_link

    return vless_link


# ------------------------------ Trojan Link Gen ------------------------------- #


def trojan_link_generator(password, port, security, type, path, name) -> str:
    """
    generate trojan link with below format:
    trojan://password@ip:port?allowInsecure=insecure&security=&type=networkstream#linkname
    """
    if not args.parseconfig:
        print("")
        print(yellow + "! Use below link for your xray or v2ray client" + reset)

    prelink = "trojan://"
    raw_link = "{}@{}:{}?allowInsecure={}&security={}&type={}&path={}#{}".format(
        password, ServerIP, port, 1, security, type, path, name
    )

    trojan_link = prelink + raw_link

    return trojan_link


# ------------------------------ ShadowSocks Link Gen ------------------------------- #


def shadowsocks_link_generator() -> str:
    """
    Generate ShadowSocks link.
    Shadowsocks link is being used for importing shadowsocks config in clients.
    ShadowSocks links are also encoded with base64.
    Visit https://github.com/shadowsocks/shadowsocks-org/wiki/SIP002-URI-Scheme for SS URI Scheme.
    """

    prelink = "ss://"
    print("")
    print(yellow + "! Use below link for your ShadowSocks client" + reset)

    raw_link = bytes(
        "{}:{}@{}:{}".format(args.ssmethod, args.sspass, ServerIP, PORT),
        encoding="ascii",
    )

    link = base64.b64encode(raw_link)  # encode raw link

    shadowsocks_link = prelink + str(
        link.decode("utf-8")
    )  # concatenate prelink with rawlink

    return shadowsocks_link


# ------------------------------ QRCode Gen ------------------------------- #


def qrcode(data, width=76, height=76) -> str:
    qrcode = Request(
        "https://qrcode.show/{}".format(data),
        headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/octet-stream",
            "X-QR-Version-Type": "micro",
            "X-QR-Quiet-Zone": "true",
            "X-QR-Min-Width": width,
            "X-QR-Min-Height": height,
        },
    )

    with urlopen(qrcode) as response:
        return response.read().decode()


# ------------------------------ Nginx Template ------------------------------- #


def nginx():
    """
    nginx template for forwarding v2ray service with nginx
    """

    #     if args.header :
    #         nginx = """http {
    #     map $http_upgrade $connection_upgrade {
    #         default upgrade;
    #         '' close;
    #     }

    #     upstream websocket {
    #         server %s:%s;
    #     }

    #     server {
    #         listen 1080;
    #         location %s {
    #         proxy_pass http://websocket;
    #         proxy_http_version 1.1;
    #         proxy_set_header Upgrade $http_upgrade;
    #         proxy_set_header Connection $connection_upgrade;
    #         proxy_set_header Host $host;
    #         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #         proxy_set_header X-Real-IP $remote_addr;

    #         }
    #     }
    # }"""%(ServerIP,PORT,args.wspath)

    nginx = """stream {
    upstream external {
        server %s:%s;  }
    server {
        listen     1080;
        proxy_pass external ; }  }""" % (
        ServerIP,
        PORT,
    )

    return nginx


# ----------------------------- argparse Conditions ----------------------------- #


def shadowsocks_check():
    # Below methods are the recommended choice.
    # Other stream ciphers are implemented but do not provide integrity and authenticity.

    methodlist = [
        "2022-blake3-chacha20-poly1305",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-aes-128-gcm",
        "xchacha20-ietf-poly1305",
        "aes-256-gcm",
        "aes-128-gcm",
        "chacha20-ietf-poly1305",
    ]
    xraymethod = methodlist[0:4]
    v2raymethod = methodlist[4:]

    if args.ssmethod not in methodlist:
        print("Select one method :")
        print("{}XRay Ciphers :{}".format(yellow, reset))

        for xmethods in range(len(xraymethod)):
            print(green + xraymethod[xmethods] + reset)

        print("{}V2ray Ciphers : {}".format(yellow, reset))
        for vmethods in range(len(v2raymethod)):
            print(green + v2raymethod[vmethods] + reset)
        sys.exit(2)

    elif args.ssmethod in (methodlist[0:2], methodlist[-1]):
        print(
            "{}{} are only useable in xray-core{}".format(yellow, args.ssmethod, reset)
        )


# def outbounds_check():
#     if args.outbound not in protocol_list:  # list of outband protocols
#         print(yellow + "! Use --outband to set method" + reset),
#         print("List of outband methods :")
#         for protocol in range(len(protocol_list)):
#             protocol_list[2] = "both : freedom + blackhole"
#             print(green + protocol_list[protocol] + reset)
#         sys.exit(2)


def dns_check():
    if args.dns not in dnslist:  # list of DNS
        print("List of Avalible DNS :")
        for dnsnames in range(len(dnslist)):
            dnslist[2] = "both : google + cloudflare"
            print(green + dnslist[dnsnames] + reset)
        sys.exit(2)


# ------------------------------ Error Messages ------------------------------- #


def base_error(err):
    return sys.exit(error + "ERROR : " + reset + str(err))


# ----------------------------- argparse Actions ----------------------------- #

if __name__ == "__main__":
    python_version()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    else:
        banner()

    # Collect Server IP
    try:
        if not args.parse:
            ServerIP = ip()
    except RemoteDisconnected as e:
        sys.exit(error + "ERROR : " + reset + str(e))
    except URLError as e:
        sys.exit(error + "ERROR : " + reset + str(e))

    user_permission()

    if args.protocols:
        protocols_list()
        sys.exit(1)

    if args.agent:
        clearcmd()
        launch_agent()

    # install bbr
    if args.bbr:
        install_bbr()

    if args.parse:
        parseLink(args.parse)

    if args.alterid > 64:
        sys.exit(error + "ERROR : " + reset + "alterid can't be more than 64")

    # set log to 'error' by default
    if args.loglevel == None:
        LOG = "error"
    else:
        loglevel()

    # set security to 'auto' by default
    if args.security == None:
        SECURITY = "auto"
    else:
        client_security()

    # call DNS func
    if args.dns:
        dnsselect()
        dns_check()

        DNS_SERVERS = {
            "both": dnsserver[0],
            "google": dnsserver[1],
            "cloudflare": dnsserver[2],
            "opendns": dnsserver[3],
            "quad9": dnsserver[4],
            "adguard": dnsserver[5],
            "nodns": NODNS,
        }
        DNS = DNS_SERVERS.get(args.dns, dnsserver[0])

    # Set To NODNS
    else:
        DNS = ""

    if args.csocks:
        SOCKSPORT = args.csocks
    if args.chttp:
        HTTPPORT = args.chttp

    # JSON custom template load
    if args.header:
        with open(args.header.name, "r") as setting:
            stream = setting.read()
            args.header = stream
    else:
        args.header = headersettings("in")

    # Insecure option
    if args.insecure == True:
        args.insecure = "true"
    if args.insecure == False:
        args.insecure = "false"

    if args.tls and args.xtls:
        sys.exit("{}ERROR : Can't use xtls and tls togheter.{}".format(error, reset))

    # Port Settings :
    if args.port == None and args.vless == True or args.tls == True:
        PORT = 443

    if args.port == None:
        pass
    else:
        PORT = args.port

    # Custom uuid
    if args.uuid == None:
        args.uuid = UUID
    else:
        UUID = args.uuid

    if args.tpass == None:
        trojanpassword = get_random_charaters(32)
    else:
        trojanpassword = args.tpass

    # # Check WebSocket Domain Status Code
    # if args.domain :
    #     websocket_domaincheck()
    #     print(green + 'Domain ٰValid!' + reset)
    #     ServerIP = f"{args.domain}"

    # ShadowSocks Method
    if args.ssmethod == None:
        args.ssmethod = "2022-blake3-chacha20-poly1305"

    # ShadowSocks Password
    if args.sspass == None and args.ssmethod == "2022-blake3-aes-128-gcm":
        args.sspass = openssl_rand("base64", 16)

    if args.sspass == None:
        args.sspass = openssl_rand("base64", 32)

    # link security method
    if args.tls:
        TLSTYPE = "tls"

    elif args.xtls:
        TLSTYPE = "xtls"

    elif args.vless or args.trojan:
        TLSTYPE = "tls"

    if args.tcp:
        net = "tcp"
        path = "/"
        header = "http"

    elif args.trojan and args.xtls:
        net = "tcp"
        path = "/"
        header = "http"

    else:
        net = "ws"
        path = args.wspath
        header = "none"

    if args.v2ray:
        linkname = "v2ray"
    else:
        linkname = "xray"

    if args.linkname == None:
        args.linkname = linkname

    proto_type = protocol_map()

    if args.vmess and args.xtls:
        sys.exit("{}! XTLS doesn't supports VMess for now.{}".format(error, reset))

    # Quick VMess Setup
    if all((args.vmess, args.tls)):
        xray_create("VMESS")
    elif args.vmess:
        xray_create("VMESS")
    # Quick Vless Setup
    elif args.vless:
        xray_create("VLESS")
    # Quick Trojan Setup
    elif args.trojan:
        xray_create("TROJAN")
    # Quick ShadowSocks Setup
    elif args.shadowsocks:
        shadowsocks_check()
        xray_create("SHADOWSOCKS")

    # Make docker-compose for VMess
    if args.dockerfile:
        xray_dockercompose()

    # Run docker-compose
    if args.dockerup:
        run_docker()

    # add firewall rules
    if args.firewall:
        firewall_config()

    # block torrent manually
    if args.block or args.blockir:
        block_torrent_manually()

    # parse configuration file
    try:
        if args.parseconfig:
            read_serverside_configuration(args.parseconfig.name)
    except json.decoder.JSONDecodeError as e:
        sys.exit(error + "ERROR: " + reset + str(e))
