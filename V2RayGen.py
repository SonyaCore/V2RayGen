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
from urllib.parse import unquote
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from http.client import RemoteDisconnected
from binascii import Error

import EnvHandler as env

# -------------------------------- Constants --------------------------------- #

# Name
NAME = "XRayGen"

# Version
VERSION = "1.0.3"

# UUID Generation
UUID = uuid.uuid4()

# Config Name
VMESS, VLESS = "config.json", "config.json"
SHADOWSOCKS = "shadowsocks.json"
OBFS = "docker-compose.yml"

SELFSIGEND_CERT = "host.cert"
SELFSIGEND_KEY = "host.key"

# PORT
PORT = 80

# Docker Compose Version
DOCKERCOMPOSEVERSION = "2.13.0"
# Docker Compose FILE
DOCKERCOMPOSE = "docker-compose.yml"

# Client Side PORT
SOCKSPORT = 2080
HTTPPORT = 2081

# -------------------------------- Colors --------------------------------- #

# Color Format
green = "\u001b[32m"
yellow = "\u001b[33m"
blue = "\u001b[34m"
error = "\u001b[31m"
reset = "\u001b[0m"

# -------------------------------- Argument Parser --------------------------------- #

usage = f"python3 {NAME} {error} <protocol> {reset} {blue} <optional args> {reset}"
formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=64)
parser = argparse.ArgumentParser(prog=f"{NAME}", formatter_class=formatter, usage=usage)


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif v.lower() in ("no", "false", "f", "n", "0"):
        return False
    else:
        raise argparse.ArgumentTypeError("Boolean value expected.")


quick = parser.add_argument_group(f"{green}Protocols{reset}")

quick.add_argument("--vmess", "-vm", action="store_true", help="Create VMess")
quick.add_argument("--vmesstls", "-vmtls", action="store_true", help="Create VMess + TLS")
quick.add_argument("--vless", "-vl", action="store_true", help="Create VLess + TLS")
quick.add_argument("--shadowsocks", "-ss", action="store_true", help="Create ShadowSocks",
)

panel = parser.add_argument_group(f"{green}Panels{reset}")

panel.add_argument(
    "--xui",
    "-xui",
    action="store_true",
    help="Setup X-Ui with the official installer script",
)
panel.add_argument(
    "--trojanpanel",
    "-tp",
    action="store_true",
    help="Setup Trojan Panel with the official installer script",
)

xray = parser.add_argument_group(f"{green}XRay{reset}")

xray.add_argument(
    "--linkname",
    "-ln",
    action="store",
    type=str,
    metavar="",
    help="Name for Xray generated link. default: [xray]",
    default="xray",
)

xray.add_argument(
    "--outband",
    "--outband-protocol",
    action="store",
    type=str,
    metavar="",
    help="Custom Xray outbound connection. default: [both]",
)

xray.add_argument(
    "--port",
    "-p",
    action="store",
    type=int,
    metavar="",
    help="Optional PORT for Xray Config. defualt: [80,443]",
)

xray.add_argument(
    "--dns", action="store", type=str, metavar="", help="Optional DNS. default: [nodns]"
)

xray.add_argument(
    "--wspath",
    "--websocket-path",
    action="store",
    type=str,
    metavar="",
    help="Optional WebSocket path. default: [/graphql]",
    default="/graphql",
)

xray.add_argument(
    "--uuid",
    "-u",
    action="store",
    type=str,
    metavar="",
    help="Optional UUID / ID for configuration. default: [random]",
    default=f"{UUID}",
)

xray.add_argument(
    "--alterid",
    "-id",
    action="store",
    type=int,
    metavar="",
    help="Optional alterId for configuration. default: [0]",
    default=0,
)

xray.add_argument(
    "--loglevel",
    "--vmess-loglevel",
    action="store",
    type=str,
    metavar="",
    help="Loglevel for Xray config. default: [warning]",
)

xray.add_argument(
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

xray.add_argument(
    "--header",
    "--http-header",
    action="store",
    type=argparse.FileType("r"),
    metavar="",
    help="Optional JSON HTTPRequest Header.",
)

xray.add_argument(
    "--block",
    "--block-routing",
    action="store_true",
    help="Adding Blocking Bittorrent and Ads. [default: False]",
)

client = parser.add_argument_group(f"{green}XRay Client Configuration{reset}")

client.add_argument(
    "--security",
    "--client-security",
    action="store",
    type=str,
    metavar="",
    help="Security for Client-side JSON config. default: [auto]",
)

client.add_argument(
    "--socks",
    "--clientsocks",
    action="store",
    type=int,
    metavar="",
    help=f"SOCKS port for Client-side JSON config. default: [{SOCKSPORT}]",
)
client.add_argument(
    "--http",
    "--clienthttp",
    action="store",
    type=int,
    metavar="",
    help=f"HTTP port for Client-side JSON config. default: [{HTTPPORT}]",
)

shadowsocks = parser.add_argument_group(f"{green}ShadowSocks{reset}")

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
    help="Set Method for ShadowSocks. default: [chacha20-ietf-poly1305]",
)

docker = parser.add_argument_group(f"{green}Docker{reset}")

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

parseurl = parser.add_argument_group(f"{green}Link Parse{reset}")

parseurl.add_argument(
    "--parse",
    "--parseurl",
    action="store",
    type=str,
    metavar="",
    help=f"Parse encoded link. supported formats: [vmess://,ss://]",
)

parseurl.add_argument(
    "--parseconfig",
    "--readconfig",
    action="store",
    type=argparse.FileType("r"),
    metavar="",
    help=f"Parse Configuration file",
)

firewall = parser.add_argument_group(f"{green}Firewall{reset}")

firewall.add_argument(
    "--firewall",
    "-fw",
    action="store_true",
    help="Adding firewall rules after generating configuration",
)

# xray.add_argument(
#     "--domain",
#     "--domain-websocket",
#     action="store",
#     type=str,
#     metavar="",
#     help="Use Domain insted of IP for WebSocket. default: [ServerIP]",
# )

opt = parser.add_argument_group(f"{green}info{reset}")
opt.add_argument("-v", "--version", action="version", version="%(prog)s " + VERSION)

# Arg Parse
args = parser.parse_args()

# ------------------------------ Miscellaneous ------------------------------- #

# Banner
def banner(t=0.0005):
    data = f"""{green}
 __   __ _____              _____            
 \ \ / /|  __ \            / ____|           
  \ V / | |__) |__ _ _   _| |  __  ___ _ __  
   > <  |  _  // _` | | | | | |_ |/ _ \ '_ \ 
  / . \ | | \ \ (_| | |_| | |__| |  __/ | | |
 /_/ \_\|_|  \_\__,_|\__, |\_____|\___|_| |_|
                     __/ |                  
                    |___/                   
{reset}"""
    for char in data:
        sys.stdout.write(char)
        time.sleep(t)
    sys.stdout.write("\n")


# Return IP
def IP():
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
            + f'failed to send request to {url.split("/json")[0]} please check your connection'
            + reset
        )
        sys.exit(1)

def get_random_suffix(size=6, chars=string.ascii_uppercase + string.digits):
    # TODO check the sequence of characters that were used
    # before to avoid making a duplicate name
    """
    Use to create random str for creating new container's name
    to use in docker-compose 
    """
    # use current directory chars as seed for our random name
    chars = os.getcwd().replace("/", "").replace(" ","")
    return ''.join(random.choice(chars) for _ in range(size))

def get_random_password(length=24):
    """
    Get random password pf length with letters, digits, and symbols
    """

    characters = string.ascii_letters + string.digits
    password = "".join(random.choice(characters) for i in range(length))

    return password


def COUNTRY():
    """
    return Country Code of the server.
    country code are used for detecting server location
    if server are not in the filtered list nginx template will be generated
    """
    try:
        countrycode = "http://ip-api.com/json/?fields=countryCode"
        httprequest = Request(countrycode, headers={"Accept": "application/json"})

        with urlopen(httprequest) as response:
            data = json.loads(response.read().decode())

        if data["countryCode"] not in ("IR", "CN", "VN"):
            print(
                yellow
                + f"\n! You Are Using External Server [{data['countryCode']}]\n"
                + "Nginx Template:"
                + reset
            )
            print(nginx())
            print(yellow + "! Append to /etc/nginx/nginx.conf" + reset)
    except HTTPError:
        print(
            error
            + f'failed to send request to {countrycode.split("/json")[0]} please check your connection'
            + reset
        )
        sys.exit(1)


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
    print(green)
    subprocess.run(
        f"openssl req -new -newkey rsa:4096 -days 735 -nodes -x509 \
    -subj '/C=UK/ST=Denial/L=String/O=Dis/CN=www.ray.uk' -keyout {SELFSIGEND_KEY} -out {SELFSIGEND_CERT}",
        shell=True,
        check=True,
    )
    print(reset)


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


# -------------------------------- Global Variables --------------------------------- #

# Collect Server IP
try:
    if not args.parse:
        ServerIP = IP()
except RemoteDisconnected as e:
    sys.exit(error + "ERROR : " + reset + str(e))
except URLError as e:
    sys.exit(error + "ERROR : " + reset + str(e))

if args.v2ray:
    PROTOCOL = "v2ray"
else :
    PROTOCOL = "xray"

# Certificate location
crtkey = f"/etc/{PROTOCOL}/{SELFSIGEND_CERT}"
hostkey = f"/etc/{PROTOCOL}/{SELFSIGEND_KEY}"

# Outband protocols
protocol_list = ["freedom", "blackhole", "both"]

# link schematic
vmess_scheme = "vmess://"
shadowsocks_scheme = "ss://"

# Supported XRay Configuration Protocols
supported_typo = ["vmess", "vmesstls", "vless"]


# -------------------------------- VMess JSON --------------------------------- #


def xray_make():
    """
    Make JSON config which reads --outband for making v2ray vmess config with specific protocol
    https://www.v2ray.com/en/configuration/protocols/v2ray.html
    """
    # Config Protocol Method
    if args.vmess:
        name = "VMESS"
        make_xray("vmess")
    elif args.vmesstls:
        name = "VMESS + TLS"
        make_xray("vmess")
    elif args.vless:
        name = "VLESS"
        make_xray("vless")
    else:
        None

    print(blue + f"! {name} Config Generated." + reset)


def xray_config(outband, protocol) -> str:
    """
    Xray JSON config file template
    """

    data = """{
    %s
    %s,
  "inbounds": [
    {
        %s
        "port": %s,
        %s,
        "streamSettings":
            %s,
            %s,
            "headersettings": %s
    }
        }
  ],
  "outbounds": [
    %s
  ]%s
}""" % (
        DNS,
        log(),
        sniffing() + "," if args.block else "",
        PORT,
        protocol,
        websocket_config(args.wspath),
        tlssettings() if args.vmesstls or args.vless else notls(),
        args.header,
        outband,
        ",\n" + routing() if args.block else "",
    )

    return json.loads(data)


# -------------------------------- Xray Config --------------------------------- #


def make_xray(protocol):
    """
    make xray config based on selected protocol
    """

    # Config Protocol Method
    if args.outband == "freedom":
        with open(VLESS, "w") as txt:
            if protocol == "vless":
                txt.write(
                    json.dumps(
                        xray_config(outband=freedom(), protocol=vless_server_side()),
                        indent=2,
                    )
                )
            elif protocol == "vmess":
                txt.write(
                    json.dumps(
                        xray_config(outband=freedom(), protocol=vmess_server_side()),
                        indent=2,
                    )
                )
            txt.close

    if args.outband == "blackhole":
        with open(VLESS, "w") as txt:
            if protocol == "vless":
                txt.write(
                    json.dumps(
                        xray_config(outband=blackhole(), protocol=vless_server_side()),
                        indent=2,
                    )
                )
            elif protocol == "vmess":
                txt.write(
                    json.dumps(
                        xray_config(outband=blackhole(), protocol=vmess_server_side()),
                        indent=2,
                    )
                )
            txt.close

    if args.outband == "both":
        with open(VLESS, "w") as txt:
            if protocol == "vless":
                txt.write(
                    json.dumps(
                        xray_config(
                            outband=freedom() + ",\n" + blackhole(),
                            protocol=vless_server_side(),
                        ),
                        indent=2,
                    )
                )
            elif protocol == "vmess":
                txt.write(
                    json.dumps(
                        xray_config(
                            outband=freedom() + ",\n" + blackhole(),
                            protocol=vmess_server_side(),
                        ),
                        indent=2,
                    )
                )
            txt.close


# -------------------------------- ShadowSocks JSON --------------------------------- #


def shadowsocks_make(method) -> str:

    shadowsocks_check()

    with open(SHADOWSOCKS, "w") as txt:
        txt.write(
            json.dumps(shadowsocks_config(method, password=args.sspass), indent=2)
        )
        txt.close

    print(blue + "! ShadowSocks Config Generated." + reset)


def shadowsocks_config(method, password) -> str:

    timeout = 300

    shadowsocks = """{
    "server":"%s",
    "server_port":%s,
    "password":"%s",
    "timeout":%s,
    "method":"%s",
    "fast_open": true
}""" % (
        ServerIP,
        PORT,
        password,
        timeout,
        method,
    )
    return json.loads(shadowsocks)


# -------------------------------- JSON Configuration --------------------------------- #


def vmess_server_side():
    """
    vmess server side inbound configuration
    https://www.v2fly.org/config/protocols/vmess.html
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


def vless_server_side():
    """
    vless server side inbound configuration
    https://www.v2fly.org/config/protocols/vless.html
    """
    vless = """
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "%s",
            "level": 0,
            "email": "love@example.com"
          }
        ],
        "decryption": "none"
      }""" % (
        UUID
    )
    return vless


def routing() -> str:
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
        "outboundTag": "block",
        "protocol": ["bittorrent"]
      },
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "outboundTag": "block",
        "domain": ["geosite:category-ads-all"]
      }
    ]
  }"""
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
          "tls",
          "quic"
        ]
      }
    """
    return data


def tlssettings() -> str:
    """
    tls security settings for protocols with tls
    """
    tls = """
    "security": "tls",    
    "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [
            {
              "certificateFile": "%s",
              "keyFile": "%s"
            }
          ]
        }""" % (
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

    websocket = """{
          "network": "ws",
          "wsSettings": {
            "connectionReuse": true,
            "path": "%s"
          }""" % (
        path
    )
    return websocket


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


def headersettings() -> str:
    """
    default tcp setting header for json configuration.
    for using custom configuration use ( --header file.json ) option to configure your own header
    """
    data = """{
            "header": {
              "type": "http",
              "response": {
                "version": "1.1",
                "status": "200",
                "reason": "OK",
                "headers": {
                  "Content-Type": [
                    "application/octet-stream",
                    "application/x-msdownload",
                    "text/html",
                    "application/x-shockwave-flash"
                  ],
                  "Transfer-Encoding": ["chunked"],
                  "Connection": ["keep-alive"],
                  "Pragma": "no-cache"
                }
              }
            }
          }"""
    return data


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

    # client protocol settings based on protocol argument
    if protocol == "VMESS":
        setting = vmess_client
    elif protocol == "VMESSTLS":
        setting = vmess_client
    elif protocol == "VLESS":
        setting = vless_clinet

    inbounds = """
        "inbounds": [
        {
        "listen": "127.0.0.1",
        "port": %s,
        "protocol": "socks",
        "settings": {
            "auth": "noauth",
            "udp": true,
            "userLevel": 8
        },
        %s
        "tag": "socks-in"
        },
        {
        "listen": "127.0.0.1",
        "port": %s,
        "protocol": "http",
        "settings": {
            "userLevel": 8
        },
        "tag": "http-in"
        }
    ]""" % (
        SOCKSPORT,
        sniffing() + "," if args.block else "",
        HTTPPORT,
    )

    tls_client = """
        "security": "tls",
        "tlsSettings": { "allowInsecure": true }
        """

    streamsettings_client = """
        "streamSettings": {
        "network": "ws",
        %s,
        "wsSettings": { "path": "%s" }
      },
      "tag": "proxy"
    """ % (
        tls_client if protocol == "VMESSTLS" or "VLESS" else notls(),
        args.wspath,
    )

    outbands_client = """
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "freedom", "tag": "bypass" },
    { "protocol": "blackhole", "tag": "block" },
    """
    policy = """
    "policy": {
    "levels": { "1": { "connIdle": 30 } },
    "system": { "statsOutboundDownlink": true, "statsOutboundUplink": true }
  }"""

    outbands = """
    "outbounds": [
    {
      "domainStrategy": "AsIs",
      %s,
      %s
    },
    %s
    {
      "protocol": "dns",
      "proxySettings": { "tag": "proxy", "transportLayer": true },
      "settings": {
        "address": "8.8.8.8",
        "network": "tcp",
        "port": 53,
        "userLevel": 1
      },
      "tag": "dns-out"
    }
  ],
    """ % (
        setting,
        streamsettings_client,
        outbands_client,
    )

    client_configuration = """
    {
        %s,
        "log": { "loglevel": "%s" },
        %s
        %s
    }
    """ % (
        inbounds,
        LOG,
        outbands,
        policy,
    )

    name = f"client-{protocol}-{args.linkname}.json"
    with open(name, "w") as wb:
        wb.write(json.dumps(json.loads(client_configuration), indent=2))
        wb.close

        print("")
        filename = green + name + reset
        print(blue + "! Client-side VMess Config Generated.", reset)
        print(
            blue + f"! Use {filename}{blue} for using proxy with xray-core directly.",
            reset,
        )

# -------------------------------- Config Creation --------------------------------- #


def xray_create(protocol):
    dnsselect()
    xray_make()

    outbounds_check()
    if protocol == "VMESS":
        xray_dockercompose("VMESS")
    elif protocol == "VMESSTLS":
        create_key()
        time.sleep(0.5)
        xray_dockercompose("VMESSTLS")
    elif protocol == "VLESS":
        create_key()
        time.sleep(0.5)
        xray_dockercompose("VLESS")

    run_docker()
    serverside_info_raw()

    if protocol == "VMESS" or protocol == "VMESSTLS":
        print(
            vmess_link_generator(
                args.alterid, UUID, "ws", args.wspath, PORT, args.linkname, tlstype
            )
        )
        if protocol == "VMESS":
            client_side_configuration("VMESS")
        elif protocol == "VMESSTLS":
            client_side_configuration("VMESSTLS")

    elif protocol == "VLESS":
        print(
            vless_link_generator(UUID, PORT, "ws", args.wspath, tlstype, args.linkname)
        )
        client_side_configuration("VLESS")
    COUNTRY() if protocol == "VMESS" else None


def shadowsocks_create():
    """
    Quick shadowsocks configuration
    """
    shadowsocks_make(args.ssmethod)
    shadowsocks_dockercompose()
    run_docker()
    print(shadowsocks_link_generator())
    COUNTRY()


# -------------------------------- Panels  --------------------------------- #


def panels(type):
    """
    installing the panel automates the process of deploying v2ray configuration with a simple UI
    but it may not works properly.
    """

    if type == "XUI":
        appname = "X-UI"
    elif type == "Trojan-Panel":
        appname = "Trojan-Panel"
    msg = f"{green + appname + reset} may install unnecessary binaries. press {error}Ctrl+C{reset} to cancel the installation."

    try:
        # installing x-ui using official installation script.
        if type == "XUI":
            print(msg)
            time.sleep(5)
            subprocess.run(
                "curl https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh | bash",
                shell=True,
                check=True,
                executable="/bin/bash",
            )

        # installing trojan-panel using official installation script.
        elif type == "Trojan-Panel":
            print(msg)
            time.sleep(5)
            subprocess.run(
                "source <(curl -L https://github.com/trojanpanel/install-script/raw/main/install_script.sh)",
                shell=True,
                check=True,
                executable="/bin/bash",
            )

    except subprocess.CalledProcessError as e:
        print(error + "Root privileges required!")


# -------------------------------- Parse URL --------------------------------- #


def parseLink(link):
    if link.startswith(vmess_scheme):
        print(parse_VMess(link))
    elif link.startswith(shadowsocks_scheme):
        print(parse_ShadowSocks(link))
    else:
        links = vmess_scheme, shadowsocks_scheme
        print(
            f"{error}ERROR:{reset} --parse arg supports only {green} {links} {reset} links"
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


def xray_dockercompose(protocol):
    """
    Create docker-compose file for xray-core.
    in this docker-compose xray-core is being used for running xray in the container.
    https://hub.docker.com/r/teddysun/xray
    """

    # docker protocol type
    if protocol == "VMESS":
        arg = VMESS
    if protocol == "VMESSTLS":
        arg = VMESS
    elif protocol == "VLESS":
        arg = VLESS

    if args.v2ray:
        type = "v2ray"
    else :
        type = "xray"

    docker_crtkey = f"- ./{SELFSIGEND_CERT}:/etc/{type}/{SELFSIGEND_CERT}:ro"
    docker_hostkey = f"- ./{SELFSIGEND_KEY}:/etc/{type}/{SELFSIGEND_KEY}:ro"
    container_name = protocol + "_" + get_random_suffix(10)
    env.create_env()
    env.set_var("COMPOSE_PROJECT_NAME", container_name.strip())
    if args.v2ray :
            data = """version: '3'
services:
  v2ray:
    image: v2fly/v2fly-core
    name: %s
    restart: always
    network_mode: host
    environment:
      - COMPOSE_PROJECT_NAME= %s
      - V2RAY_VMESS_AEAD_FORCED=false
    entrypoint: ["v2ray", "run", "-c", "/etc/v2ray/config.json"]
    volumes:
        - ./%s:/etc/v2ray/config.json:ro
        %s
        %s""" % (
        container_name,
        container_name,
        arg,
        docker_crtkey if args.vless or args.vmesstls else "",
        docker_hostkey if args.vless or args.vmesstls else "",
    )
    else :
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
        arg,
        docker_crtkey if args.vless or args.vmesstls else "",
        docker_hostkey if args.vless or args.vmesstls else "",
    )

    print(yellow + f"! Created xray-core {DOCKERCOMPOSE} configuration" + reset)
    with open(f"{DOCKERCOMPOSE}", "w") as txt:
        txt.write(data)
        txt.close()


def shadowsocks_dockercompose():
    """
    Create ShadowSocks docker-compose file for shadowsocks-libev.
    in this docker-compose shadowsocks-libev is being used for running shadowsocks in the container.
    https://hub.docker.com/r/shadowsocks/shadowsocks-libev
    """

    data = """version: '3'
services:
  shadowsocks:
    image: shadowsocks/shadowsocks-libev
    ports:
      - "%s:8388"
    environment:
      - TIMEOUT=300
      - METHOD=%s
      - PASSWORD=%s
    restart: always""" % (
        PORT,
        args.ssmethod,
        args.sspass,
    )

    print(yellow + f"! Created ShadowSocks {DOCKERCOMPOSE} configuration" + reset)
    with open(f"{DOCKERCOMPOSE}", "w") as txt:
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
                f"docker-compose -f {DOCKERCOMPOSE} up -d", shell=True, check=True
            )
            reset_docker_compose()
        else:
            print(
                yellow
                + f"docker-compose Not Found.\nInstalling docker-compose v{DOCKERCOMPOSEVERSION} ..."
            )
            subprocess.run(
                f"curl -SL https://github.com/docker/compose/releases/download/v{DOCKERCOMPOSEVERSION}/docker-compose-linux-x86_64 \
        -o /usr/local/bin/docker-compose",
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
                f"docker-compose -f {DOCKERCOMPOSE} up -d", shell=True, check=True
            )
    except subprocess.CalledProcessError as e:
        sys.exit(error + str(e) + reset)
    except PermissionError:
        sys.exit(error + "ًroot privileges required" + reset)


def reset_docker_compose():
    subprocess.run(f"docker-compose restart", shell=True, check=True)


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
            subprocess.run(f"ufw allow {PORT}", check=True, shell=True)
        elif os.path.exists("/usr/sbin/firewalld"):
            service = "firewalld"
            subprocess.run(
                f"firewall-cmd --permanent --add-port={PORT}/tcp",
                shell=True,
                check=True,
            )
        else:
            service = "iptables"
            subprocess.run(
                f"iptables -t filter -A INPUT -p tcp --dport {PORT} -j ACCEPT",
                shell=True,
                check=True,
            )
            subprocess.run(
                f"iptables -t filter -A OUTPUT -p tcp --dport {PORT} -j ACCEPT",
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
    print("")
    print("SERVER SIDE Information : ")
    print("IP: " + blue + str((ServerIP)) + reset)
    print("ID: " + blue + str(args.alterid) + reset)
    print("LOGLEVEL: " + blue + str(LOG) + reset)
    print("UUID: " + blue + str(UUID) + reset)
    print("WSPATH: " + blue + str(args.wspath) + reset)
    print("PORT: " + blue + str(PORT) + reset)
    print("SECURITY: " + blue + str(tlstype) + reset)
    print("LINKNAME: " + blue + str(args.linkname) + reset)

    if args.socks or args.http:
        print("")
        print("CLIENT SIDE Information : ")
        print("SECURITY : " + blue + str(SECURITY) + reset)
        print("HTTP PORT : " + blue + str(HTTPPORT) + reset)
        print("SOCKS PORT : " + blue + str(SOCKSPORT) + reset)


def read_serverside_configuration(config):
    """
    parse server-side configuration file
    this function only support vmess & vless json file
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
        securitymethod = data["inbounds"][0]["streamSettings"]["security"]

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

    except KeyError as e:
        sys.exit(error + "ERROR: " + str(e) + f" not found in {config}!")


def link_serverside_configuration():
    """
    generate link with server-side configuration file.
    """
    if protocol == "vmess":
        return vmess_link_generator(
            AlterId, ID, net, path, configport, "xray", securitymethod
        )
    elif protocol == "vless":
        return vless_link_generator(ID, configport, net, path, securitymethod, "xray")


# ------------------------------ VMess Link Gen ------------------------------- #


def vmess_link_generator(aid, id, net, path, port, ps, tls) -> str:
    """
    Generate vmess link.

    vmess link is being used for importing v2ray config in clients.
    vmess links are encoded with base64.
    """

    if not ps:
        ps = "xray"

    if not args.parseconfig:
        print("")
        print(yellow + "! Use below link for your xray or v2ray client" + reset)

    prelink = "vmess://"
    raw_link = bytes(
        "{"
        + f""""add":"{ServerIP}",\
"aid":"{aid}",\
"host":"",\
"id":"{id}",\
"net":"{net}",\
"path":"{path}",\
"port":"{port}",\
"ps":"{ps}",\
"tls":"{tls}",\
"type":"none",\
"v":"2" """
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
    raw_link = f"{id}@{ServerIP}:{port}?path={path}&security={security}&encryption=none&type={net}#{name}"

    vless_link = prelink + raw_link

    return vless_link


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
        f"{args.ssmethod}:{args.sspass}@{ServerIP}:{PORT}", encoding="ascii"
    )

    link = base64.b64encode(raw_link)  # encode raw link

    shadowsocks_link = prelink + str(
        link.decode("utf-8")
    )  # concatenate prelink with rawlink

    return shadowsocks_link


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

    methodlist = ["chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm"]
    if args.ssmethod not in methodlist:
        print("Select one method :")
        for methods in range(len(methodlist)):
            print(green + methodlist[methods] + reset)
        sys.exit(2)


def outbounds_check():
    if args.outband not in protocol_list:  # list of outband protocols
        print(yellow + "! Use --outband to set method" + reset),
        print("List of outband methods :")
        for protocol in range(len(protocol_list)):
            protocol_list[2] = "both : freedom + blackhole"
            print(green + protocol_list[protocol] + reset)
        sys.exit(2)


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

    if len(sys.argv) <= 1:
        parser.print_help()
    else:
        banner()

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

    # Set To NODNS
    else:
        DNS = ""

    # DNS argument parser
    if args.dns == "both":
        DNS = dnsserver[0]
    if args.dns == "google":
        DNS = dnsserver[1]
    if args.dns == "cloudflare":
        DNS = dnsserver[2]
    if args.dns == "opendns":
        DNS = dnsserver[3]
    if args.dns == "quad9":
        DNS = dnsserver[4]
    if args.dns == "adguard":
        DNS = dnsserver[5]
    if args.dns == "nodns":
        DNS = NODNS

    if args.socks:
        SOCKSPORT = args.socks
    if args.http:
        HTTPPORT = args.http

    # JSON custom template load
    if args.header:
        with open(f"{args.header.name}", "r") as setting:
            stream = setting.read()
            args.header = stream
    else:
        args.header = headersettings()

    # Insecure option
    if args.insecure == True:
        args.insecure = "true"
    if args.insecure == False:
        args.insecure = "false"

    # Port Settings :
    if args.port == None and args.vless == True or args.vmesstls == True:
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

    # # Check WebSocket Domain Status Code
    # if args.domain :
    #     websocket_domaincheck()
    #     print(green + 'Domain ٰValid!' + reset)
    #     ServerIP = f"{args.domain}"

    # ShadowSocks Password
    if args.sspass == None:
        args.sspass = get_random_password()

    # ShadowSocks Method
    if args.ssmethod == None:
        args.ssmethod = "chacha20-ietf-poly1305"

    if args.outband == None:
        args.outband = "both"

    # link security method
    if args.vmess:
        tlstype = ""
    elif args.vmesstls:
        tlstype = "tls"
    elif args.vless:
        tlstype = "tls"

    # Quick VMess Setup
    if args.vmess:
        xray_create("VMESS")
    elif args.vmesstls:
        xray_create("VMESSTLS")
    # Quick Vless Setup
    elif args.vless:
        xray_create("VLESS")
    # Quick ShadowSocks Setup
    elif args.shadowsocks:
        shadowsocks_create()

    # Install XUI
    if args.xui:
        panels("XUI")
    # Install Trojan-Panel
    if args.trojanpanel:
        panels("Trojan-Panel")

    # Make docker-compose for VMess
    if args.dockerfile:
        xray_dockercompose("VMESS")
    # Make docker-compose for ShadowSocks
    if args.ssdocker:
        shadowsocks_dockercompose()

    # Run docker-compose
    if args.dockerup:
        run_docker()

    # add firewall rules
    if args.firewall:
        firewall_config()

    # parse configuration file
    try:
        if args.parseconfig:
            read_serverside_configuration(args.parseconfig.name)
    except json.decoder.JSONDecodeError as e:
        sys.exit(error + "ERROR: " + reset + str(e))
