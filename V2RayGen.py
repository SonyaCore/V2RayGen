#!/usr/bin/env python3

# V2Ray Config Generator
# --------------------------------
# author    : SonyaCore
#	github    : https://github.com/SonyaCore

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
import logging
from urllib.request import urlopen, Request

# -------------------------------- Constants --------------------------------- #

# Name
NAME = 'V2RayGen' 

# Version
VERSION = '0.3'

# UUID Generation
UUID = uuid.uuid4()

# Config Name
VMESS = 'config.json'
SHADOWSOCKS = 'shadowsocks.json'
OBFS = 'docker-compose.yml'

# PORT
PORT = 80

# Docker Compose Version
DOCKERCOMPOSEVERSION =  '2.11.1'

# -------------------------------- Argument Parser --------------------------------- #

formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=64)
parser = argparse.ArgumentParser(prog=f'{NAME}',formatter_class=formatter)

gp = parser.add_mutually_exclusive_group()

gp.add_argument('--vmess','-vm',
action='store_true',
help='Quick VMess & Start with docker')

gp.add_argument('--shadowsocks','-ss',
action='store_true',
help='Quick ShadowSocks & Start with docker')

gp.add_argument('--obfs','-ob',
action='store_true',
help='Quick ShadowSocks-OBFS & Start with docker')


vmess = parser.add_argument_group('VMess')

vmess.add_argument('--generate','--gen',
action='store_true',
help='Generate VMess JSON config')

vmess.add_argument('--link','--vmesslink', 
action='store_true',
help='Generate vmess link for v2ray config')

vmess.add_argument('--linkname','--vmessname',
action='store' , type=str , metavar='' ,
help='Name for VMess Link. default: [v2ray]')

vmess.add_argument('--protocol','--outband',
action='store' , type=str,  metavar='' ,
help='Protocol for outbound connection. default: [freedom]')

vmess.add_argument('--port','-p',
action='store' , type=int , metavar='' ,
help='Optional PORT for v2ray Config. defualt: [80]' )

vmess.add_argument('--dns', 
action='store' , type=str, metavar='' ,
help='Optional DNS. default: [nodns]')

vmess.add_argument('--wspath',"--websocket-path",
action='store' , type=str, metavar='' ,
help='Optional WebSocket path. default: [/graphql]',default='/graphql')

shadowsocks = parser.add_argument_group('ShadowSocks')

shadowsocks.add_argument('--ssmake','--shadowsocks-make',
action='store_true' ,
help='Generate Shadowsocks JSON config')

shadowsocks.add_argument('--sspass','--shadowsocks-password',
action='store' , type=str, metavar='' ,
help='Set Password for ShadowSocks. default: [random]')

shadowsocks.add_argument('--ssmethod','--shadowsocks-method',
action='store' , type=str, metavar='' ,
help='Set Method for ShadowSocks. default: [chacha20-ietf-poly1305]')

shadowsocks.add_argument('--sslink','--shadowsockslink',
action='store_true' ,
help='Generate ShadowSocks link')

obfs = parser.add_argument_group('OBFS')

obfs.add_argument('--obfsmake','--obfs-make',
action='store_true' ,
help='Generate Shadowsocks-OBFS JSON config')

obfs.add_argument('--obfspass','--obfs-password',
action='store' , type=str, metavar='' ,
help='Set Password for ShadowSocks-OBFS. default: [random]')

obfs.add_argument('--obfsmethod','--obfs-method',
action='store' , type=str, metavar='' ,
help='Set Method for ShadowSocks-OBFS. default: [chacha20-ietf-poly1305]')

obfs.add_argument('--obfslink',
action='store_true' ,
help='Generate ShadowSocks-OBFS link')

docker = parser.add_argument_group('Docker')

docker.add_argument('--vmessdocker','--vmess-dockerfile',
action= 'store_true' , required=False ,
help='Generate VMess docker-compose file for v2ray-core')

docker.add_argument('--ssdocker','--shadowsocks-dockerfile',
action= 'store_true' , required=False ,
help='Generate ShadowSocks docker-compose file for shadowsocks-libev')


docker.add_argument('--dockerup', 
action= 'store_true' , required=False ,
help='Start docker-compose in system')

opt = parser.add_argument_group('info')
opt.add_argument('--version','-v',
action='version' , version='%(prog)s ' + VERSION)

# Arg Parse
args = parser.parse_args()
# ------------------------------ Miscellaneous ------------------------------- #

# Color Format
green = '\u001b[32m'
yellow = '\u001b[33m'
blue = '\u001b[34m'
error = '\u001b[31m'
reset = '\u001b[0m'

# Banner
def banner():
	return (f"""{green}
__      _____  _____              _____            
\ \    / /__ \|  __ \            / ____|
 \ \  / /   ) | |__) |__ _ _   _| |  __  ___ _ __  
  \ \/ /   / /|  _  // _` | | | | | |_ |/ _ \ '_ \ 
   \  /   / /_| | \ \ (_| | |_| | |__| |  __/ | | |
    \/   |____|_|  \_\__,_|\__, |\_____|\___|_| |_|
                            __/ |
                           |___/
{reset}""")

# Return IP
def IP():
  '''
  Return IP with ip-api.com
  '''
  url = "http://ip-api.com/json/?fields=query"

  if not url.startswith("http"):
      raise RuntimeError("Incorrect and possibly insecure protocol in url")

  httprequest = Request(url, headers={"Accept": "application/json"})

  with urlopen(httprequest) as response:
    data = (json.loads(response.read().decode()))
    return(data['query'])

def get_random_password(length=24):
  '''
  Get random password pf length with letters, digits, and symbols
  '''

  characters = string.ascii_letters + string.digits
  password = ''.join(random.choice(characters) for i in range(length))

  return  password

def _uuid():
  '''
  Return Randomized UUID and port after making config
  '''
  return ('UUID: ' + blue + str(UUID) + reset)

def _port():
  '''
  Return PORT  after making config
  ''' 
  return ('PORT: ' + blue + str(PORT)  + reset)

def dnsselect():
  '''
  DNS Selection
  '''

  global both , google , cloudflare , opendns , quad9 , adguard , NODNS
  global dnslist
  dnslist = ['both','google','cloudflare','opendns','quad9','adguard','nodns']

  both = """"dns": {
      "servers": [
        "8.8.8.8",
        "1.1.1.1",
        "4.2.2.4"
    ]
  },"""
  google = """"dns": {
      "servers": [
        "8.8.8.8",
        "4.2.2.4"
    ]
  },"""
  cloudflare = """"dns": {
      "servers": [
        "1.1.1.1"
    ]
  },"""

  opendns = """"dns": {
      "servers": [
        "208.67.222.222",
        "208.67.220.220"
    ]
  },"""

  quad9 = """"dns": {
      "servers": [
        "9.9.9.9",
        "149.112.112.112"
    ]
  },"""

  adguard = """"dns": {
      "servers": [
        "94.140.14.14",
        "94.140.15.15"
    ]
  },"""


  NODNS = ''

# -------------------------------- VMess JSON --------------------------------- #

def vmess_make():
  '''
  Make JSON config which reads --protocol for making v2ray config with specific protocol
  '''
  
  global protocol_list
  protocol_list = ['freedom','blackhole','both']
  
  # Show Banner
  print(banner())

  # config method
  if args.protocol == 'freedom' or None:
    with open(VMESS,'w') as txt :
      txt.write(json.dumps(vmess_config(method=freedom(),websocket=websocket(args.wspath)),
      indent= 2))
      txt.close

  if args.protocol == 'blackhole':
    with open(VMESS,'w') as txt :
      txt.write(json.dumps(vmess_config(method=blackhole()),
      indent=2))
      txt.close

  if args.protocol == 'both':
    with open(VMESS,'w') as txt :
      txt.write(json.dumps(vmess_config(method=freedom() + ',\n' + blackhole()),
      indent=2))
      txt.close

  print(blue + '! VMess Config Generated.' + reset)

def vmess_config(method,websocket) -> str:
  '''
  vmess JSON config file template
  '''

  data = """{
    %s
    "log": {
      "loglevel": "info"
    },
    "inbounds": [
      {
        "port": %s,
        "protocol": "vmess",
        "allocate": {
          "strategy": "always"
        },
        "settings": {
          "clients": [
            {
              "id": "%s",
              "level": 1,
              "alterId": 0,
              "email": "client@example.com"
            }
          ],
          "disableInsecureEncryption": true
        },
        "streamSettings": 
        %s,
          "security": "none",
          "tcpSettings": {
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
          }
        }
      }
    ],
    "outbounds": [
    %s
    ]
}
""" % (DNS,PORT,UUID,websocket,method)
  return json.loads(data)

def websocket(path) -> str:
  '''
  WebSocket stream setting template for JSON.
  by default, WebSocket is used for transporting data.
  Websocket connections can be proxied by HTTP servers such as Nginx.

  '''
  if not path :
    path = '/graphql'

  websocket = """{
          "network": "ws",
          "wsSettings": {
            "connectionReuse": true,
            "path": "%s"
          }""" % (path)
  return websocket

def freedom() -> str:
  '''
  Freedom protocol template JSON config.

  adding freedom outbound to json config
  It passes all TCP or UDP connection to their destinations.
  This outbound is used when you want to send traffic to its real destination.
  it can be used as a single outbound connection witch default --vmess arg uses.
  '''

  freedom = """ {
      "protocol": "freedom",
      "settings": {}
    }"""

  return freedom

def blackhole() -> str:
  '''
  Blackhole protocol template JSON config.

  with this fucntion blackhole outbound will be added in json
  it can be combined with freedom or as a single outbound connection
  '''

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

def vmess_simple():
  '''
  Quick VMess Configuration.
  '''

  args.protocol = 'freedom'
  dnsselect()
  vmess_make()
  vmess_dockercompose()
  run_docker()
  print(_port())
  print(_uuid())
  print(vmess_link_generator(args.linkname))


# -------------------------------- ShadowSocks JSON --------------------------------- #

def shadowsocks_make(method) -> str:
  
  print(banner())
  shadowsocks_check()


  with open(SHADOWSOCKS,'w') as txt :
    txt.write(json.dumps(shadowsocks_config(method,password=args.sspass),
    indent= 2))
    txt.close

  print(blue + '! ShadowSocks Config Generated.' + reset)

def shadowsocks_config(method,password) -> str:  

  timeout = 300
  
  shadowsocks = """{
    "server":"%s",
    "server_port":%s,
    "password":"%s",
    "timeout":%s,
    "method":"%s",
    "fast_open": true
}""" % (IP(),PORT,password,timeout,method)
  return json.loads(shadowsocks)

def shadowsocks_simple():
  '''
  Quick Shadowsocks Configuration.
  '''

  shadowsocks_make(args.ssmethod)
  shadowsocks_dockercompose()
  run_docker()
  print(shadowsocks_link_generator())

# -------------------------------- ShadowSocks OBFS --------------------------------- #

def obfs_make(method) -> str:

  print(banner())
  shadowsocks_check()

  with open(OBFS,'w') as txt :
    txt.write(obfs_config(method,password=args.obfspass))
    txt.close

  print(blue + '! ShadowSocks-OBFS Config Generated.' + reset)

def obfs_config(method,password) -> str:  

  obfs = """version: '3'
services:
    shadowsocks:
        container_name: shadowsocks
        image: shadowsocks/shadowsocks-libev
        ports:
            - "%s:8388/udp"
        networks:
            overlay:
        environment:
          - PASSWORD=%s
          - METHOD=%s
        restart: always
    simple-obfs:
      container_name: obfs
      image: gists/simple-obfs
      ports:
          - "%s:8388/tcp"
      environment:
          - FORWARD=shadowsocks:8388
      depends_on:
          - shadowsocks
      networks:
          overlay:
      restart: always

networks:
    overlay:
        driver: bridge""" % (PORT,password,method,PORT)
  return obfs


def obfs_simple():
  '''
  Quick ShadowSocks-OBFS Configuration.
  '''

  obfs_make(args.obfsmethod)
  run_docker()
  print(_port())
  print('PASSWORD: ' + blue + str(args.obfspass)  + reset)
  print(shadowsocks_link_generator())


# -------------------------------- Docker --------------------------------- #

def vmess_dockercompose():
  '''
  Create VMess docker-compose file for v2ray-core.
  in this docker-compose v2fly-core is being used for running v2ray in the container.
  '''

  data = """version: '3'
services:
  v2ray:
    image: v2fly/v2fly-core
    restart: always
    network_mode: host
    environment:
      - V2RAY_VMESS_AEAD_FORCED=false
    volumes:
        - ./%s:/etc/v2ray/config.json:ro""" % (VMESS)

  print(yellow + '! Created vmess-v2ray docker-compose.yml configuration' + reset)
  with open('docker-compose.yml','w') as txt :
    txt.write(data)
    txt.close()

def shadowsocks_dockercompose():
  '''
  Create ShadowSocks docker-compose file for shadowsocks-libev.
  in this docker-compose shadowsocks-libev is being used for running shadowsocks in the container.
  '''

  data = """shadowsocks:
  image: shadowsocks/shadowsocks-libev
  ports:
    - "%s:8388"
  environment:
    - TIMEOUT=300
    - METHOD=%s
    - PASSWORD=%s
  restart: always""" % (PORT,args.ssmethod,args.sspass)

  print(yellow + '! Created ShadowSocks docker-compose.yml configuration' + reset)
  with open('docker-compose.yml','w') as txt :
    txt.write(data)
    txt.close()

def run_docker():
  '''
  Start v2ray docker-compose.
  at first, it will check if docker exists and then check if docker-compose exists
  if docker is not in the path it will install docker with the official script.
  then it checks the docker-compose path if the condition is True docker-compose.yml will be used for running v2ray.
  '''

  # check if docker exist
  if os.path.exists('/usr/bin/docker') or os.path.exists('/usr/local/bin/docker'):
      pass
  else:
      # install docker if docker are not installed
      try:
          print(yellow + 'Docker Not Found.\nInstalling Docker ...')
          subprocess.run('curl https://get.docker.com | sh',shell=True,check=True)
      except subprocess.CalledProcessError:
          sys.exit(error + 'Download Failed !' + reset)

  time.sleep(2)

  # check if docker-compose exist
  
  if os.path.exists('/usr/bin/docker-compose') or os.path.exists('/usr/local/bin/docker-compose'):
      subprocess.run('docker-compose -f docker-compose.yml up -d',shell=True,check=True)
  else:
      print(yellow + f'docker-compose Not Found.\nInstalling docker-compose v{DOCKERCOMPOSEVERSION} ...')
      subprocess.run(f'curl -SL https://github.com/docker/compose/releases/download/v{DOCKERCOMPOSEVERSION}/docker-compose-linux-x86_64 \
      -o /usr/local/bin/docker-compose',shell=True,check=True)
      subprocess.run('chmod +x /usr/local/bin/docker-compose',shell=True,check=True)
      subprocess.run('ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose',shell=True,check=True)
      
      subprocess.run('docker-compose -f docker-compose.yml up -d',shell=True,check=True)

# ------------------------------ VMess Link Gen ------------------------------- #

def vmess_link_generator(vmess_config_name) -> str:
  '''
  Generate vmess link.

  vmess link is being used for importing v2ray config in clients.
  vmess links are encoded with base64.
  '''

  if not vmess_config_name:
    vmess_config_name = 'v2ray'

  prelink = 'vmess://'
  print(yellow + '! Use below link for your v2ray client' + reset)
  raw_link = bytes('{' + 
f""""add":"{IP()}",\
"aid":"0",\
"host":"",\
"id":"{UUID}",\
"net":"ws",\
"path":"{args.wspath}",\
"port":"{PORT}",\
"ps":"{vmess_config_name}",\
"tls":"",\
"type":"none",\
"v":"2" """ + '}',\
  encoding='ascii')

  link = base64.b64encode(raw_link) # encode raw link
  
  vmess_link = prelink + \
  str(link.decode('utf-8')) # concatenate prelink with rawlink

  return vmess_link


# ------------------------------ ShadowSocks Link Gen ------------------------------- #

def shadowsocks_link_generator() -> str:
  '''
  Generate ShadowSocks link.

  Shadowsocks link is being used for importing v2ray config in clients.
  ShadowSocks links are also encoded with base64.
  Visit https://github.com/shadowsocks/shadowsocks-org/wiki/SIP002-URI-Scheme for SS URI Scheme.
  '''

  prelink = 'ss://'
  print(yellow + '! Use below link for your ShadowSocks client' + reset)

  raw_link = bytes(f"{args.ssmethod}:{args.sspass}@{IP()}:{PORT}",
  encoding='ascii')

  link = base64.b64encode(raw_link) # encode raw link
  
  shadowsocks_link = prelink + \
  str(link.decode('utf-8')) # concatenate prelink with rawlink

  return shadowsocks_link


# ----------------------------- argparse Conditions ----------------------------- #

def shadowsocks_check():
  # Below methods are the recommended choice.
  # Other stream ciphers are implemented but do not provide integrity and authenticity.

  methodlist = ['chacha20-ietf-poly1305','aes-256-gcm','aes-128-gcm']
  if args.ssmethod not in methodlist or args.obfsmethod not in methodlist:
    raise TypeError(sys.exit(f"""Select one method :
    {green}chacha20-ietf-poly1305
    aes-256-gcm
    aes-128-gcm{reset}"""))

def protocol_check():
  if args.protocol  not in protocol_list:  # list of outband protocols
    raise TypeError(sys.exit(f"""{yellow}! Use --protocol to set method{reset}
List of outband methods :
  {green}freedom
  blackhole
  both : freedom + blackhole{reset}"""))

def dns_check():
  if args.dns not in dnslist :  # list of DNS
    raise TypeError(sys.exit(f"""List of Avalible DNS :
  {green}google
  cloudflare
  both : google + cloudflare
  opendns
  quad9
  adguard
  nodns{reset}"""))


# ----------------------------- argparse Actions ----------------------------- #

if len(sys.argv) <= 1:
    parser.print_help()

# call DNS func
if args.dns :
  dnsselect()
  dns_check()

# Set To NODNS
else:
  DNS = ''

# DNS argument parser
if args.dns == 'both':
  DNS = both
if args.dns == 'google':
  DNS = google
if args.dns == 'cloudflare':
  DNS = cloudflare
if args.dns == 'opendns':
  DNS = opendns
if args.dns == 'quad9':
  DNS = quad9
if args.dns == 'adguard':
  DNS = adguard
if args.dns == 'nodns':
  DNS = NODNS

# VMess Port :
if args.port == None :
  pass
else :
  PORT = args.port

# Make VMess Config with Defined parameters
if args.protocol or args.generate :
  vmess_make()
  protocol_check()
  print(_port())
  print(_uuid())

# ShadowSocks Password
if args.sspass == None:
  args.sspass = get_random_password()
if args.obfspass == None:
   args.obfspass = get_random_password()

# ShadowSocks Method
if args.ssmethod == None:
  args.ssmethod = 'chacha20-ietf-poly1305'
if args.obfsmethod == None :
  args.obfsmethod = 'chacha20-ietf-poly1305'

# Make ShadowSocks Config
if args.ssmake:
  shadowsocks_make(args.ssmethod)
if args.obfsmake:
  obfs_make(args.obfsmethod)
  print(_port())
  print('PASSWORD: ' + blue + args.obfspass + reset)

# Quick VMess Setup
if args.vmess:
  vmess_simple()

# Quick ShadowSocks | Shadowsocks-OBFS Setup
if args.shadowsocks:
  shadowsocks_simple()
if args.obfs:
  obfs_simple()

# Make ShadowSocks Link
if args.sslink:
  if args.ssmake is None or args.shadowsocks is None:
    parser.error('--ssmake or --shadowsocks are required')
  else:
    print(shadowsocks_link_generator())

# Make OBFS Link (Same as SS)
if args.obfslink:
  if args.obfsmake is None or args.obfs is None:
    parser.error('--obfsmake or --obfs are required')
  else:
    print(shadowsocks_link_generator())

# Make docker-compose for VMess
if args.vmessdocker :
  vmess_dockercompose()
# Make docker-compose for ShadowSocks
if args.ssdocker :
  shadowsocks_dockercompose()

# Run docker-compose
if args.dockerup:
  run_docker()

# Make VMess Link
if args.link:
  if args.generate is None or args.protocol is None:
    parser.error('--generate and --protocol are required')
  else:
    print(vmess_link_generator(args.linkname))
