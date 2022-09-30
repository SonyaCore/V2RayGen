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
import socket
import json
import logging

# -------------------------------- Constants --------------------------------- #

# Name
NAME = 'V2RayGen' 

# Version
VERSION = '0.2'

# UUID Generation
UUID = uuid.uuid4()

# Config Name
CONFIGNAME = 'config.json'

# PORT
PORT = 80

# Docker Compose Version
DOCKERCOMPOSEVERSION =  '2.11.1'

# -------------------------------- Argument Parser --------------------------------- #

formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=64)
parser = argparse.ArgumentParser(prog=f'{NAME}',formatter_class=formatter)

gp = parser.add_mutually_exclusive_group()
gp.add_argument('--vmess','-s', action='store_true',
help='generate simple vmess config and starting it with docker')

vmess = parser.add_argument_group('VMess')
vmess.add_argument('--generate','--gen', action='store_true',

help='generate vmess json config')
vmess.add_argument('--link','--vmesslink', action='store_true',
help='generate vmess link for v2ray config')

vmess.add_argument('--linkname','--vmessname', action='store' , type=str ,
help='set name for VMess Link. defualt: [v2ray]' )

vmess.add_argument('--protocol','--outband', action='store' , type=str,
help='set protcol for outband connection. default: [freedom]')

vmess.add_argument('--port','-p', action='store' , type=int ,
help='set optional port for V2Ray Config. defualt: [80]' )

vmess.add_argument('--dns', action='store' , type=str,
help='set optional dns. default: [nodns]')

docker = parser.add_argument_group('Docker')
docker.add_argument('--dockerfile', action= 'store_true' , required=False ,
help='generate docker-compose for v2ray')

docker.add_argument('--dockerup', action= 'store_true' , required=False ,
help='start v2ray docker-compose in system')

opt = parser.add_argument_group('info')
opt.add_argument('--version','-v', action='version' , version='%(prog)s ' + VERSION)

# Arg Parse
args = parser.parse_args()

# ------------------------------ Miscellaneous ------------------------------- #

# Color Format
green = '\u001b[32m'
yellow = '\u001b[33m'
blue = '\u001b[34m'
error = '\u001b[31m'
reset = '\u001b[0m'

# Return IP
def IP():
  '''
  return ip address with socket library
  '''
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.settimeout(0)
  try:
      # dummy ip
      s.connect(('10.254.254.254', 1))
      IP = s.getsockname()[0]
  except Exception:
      IP = '127.0.0.1'
  finally:
      s.close()
  return IP

def uuid_port():
  '''
  return uuid and port after making config
  '''

  print('UUID: ' + blue + str(UUID) + reset)
  print('PORT: ' + blue + str(PORT)  + reset)

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
  make json config which reads --protocol
  for making v2ray config with specific protocol
  '''
  
  global protocol_list
  protocol_list = ['freedom','blackhole','both']
    
  # config method
  if args.protocol == 'freedom' or None:
    with open(CONFIGNAME,'w') as txt :
      txt.write(json.dumps(vmess_config(method=freedom()),
      indent= 2))
      txt.close

  if args.protocol == 'blackhole':
    with open(CONFIGNAME,'w') as txt :
      txt.write(json.dumps(vmess_config(method=blackhole()),
      indent=2))
      txt.close

  if args.protocol == 'both':
    with open(CONFIGNAME,'w') as txt :
      txt.write(json.dumps(vmess_config(method=freedom() + ',\n' + blackhole()),
      indent=2))
      txt.close

def vmess_config(method) -> str:
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
        "streamSettings": {
          "network": "ws",
          "wsSettings": {
            "connectionReuse": true,
            "path": "/graphql"
          },
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
""" % (DNS,PORT,UUID,method)
  return json.loads(data)

def freedom() -> str:
  '''
  Append freedom protocol to JSON config
  '''

  freedom = """ {
      "protocol": "freedom",
      "settings": {}
    }"""

  return freedom

def blackhole() -> str:
  '''
  Append blackhole protocol to JSON config
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
  simple configuration will setup vmess config with configuration :\n
  protocol freedom\n
  dns google\n
  port 80\n
  docker compose\n
  run docker compose install docker if docker bin not exist\n
  vmess link generate
  '''

  args.protocol = 'freedom'
  dnsselect()
  vmess_make()
  v2ray_dockercompose()
  run_docker()
  uuid_port()
  print(vmess_link_generator(args.linkname))

# ------------------------------ Docker ------------------------------- #

def v2ray_dockercompose():
  '''
  Create Docker compose for v2ray core
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
        - ./%s:/etc/v2ray/config.json:ro""" % (CONFIGNAME)

  print(yellow + '! created v2ray Docker-Compose configuration' + reset)
  with open('docker-compose.yml','w') as txt :
    txt.write(data)
    txt.close()

def run_docker():
  '''
  start v2ray docker-compose
  '''

  # check if docker exist
  if os.path.exists('/usr/bin/docker') or os.path.exists('/usr/local/bin/docker'):
      pass
  else:
      # install docker if docker are not installed
      try:
          subprocess.run('curl https://get.docker.com | sudo sh',shell=True,check=True)
      except subprocess.CalledProcessError:
          print(error + 'Download Failed !' + reset)
          sys.exit()

  time.sleep(2)

  # check if docker-compose exist
  if os.path.exists('/usr/bin/docker-compose') or os.path.exists('/usr/local/bin/docker-compose'):
      subprocess.run('sudo docker-compose -f docker-compose.yml up -d',shell=True,check=True)
  else:
      subprocess.run(f'sudo curl -SL https://github.com/docker/compose/releases/download/v{DOCKERCOMPOSEVERSION}/docker-compose-linux-x86_64 \
      -o /usr/local/bin/docker-compose',shell=True,check=True)
      subprocess.run('sudo chmod +x /usr/local/bin/docker-compose',shell=True,check=True)
      subprocess.run('sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose',shell=True,check=True)
      
      subprocess.run('sudo docker-compose -f docker-compose.yml up -d',shell=True,check=True)

# ------------------------------ VMess Link Gen ------------------------------- #

def vmess_link_generator(vmess_config_name) -> str:
  '''
  generate vmess link
  '''

  if not vmess_config_name:
    vmess_config_name = 'v2ray'

  prelink = 'vmess://'
  print(yellow + '! use below link for you v2ray client' + reset)
  raw_link = bytes('{' + 
f"add:{IP()},\
aid:0,\
host:,\
id:{UUID},\
net:ws,\
path:/graphql,\
port:{PORT},\
ps:{vmess_config_name},\
tls:,\
type:none,\
v:2" + '}',\
  encoding='ascii')

  link = base64.b64encode(raw_link) # encode raw link
  
  vmess_link = prelink + \
  str(link.decode('utf-8')) # concatenate prelink with rawlink

  return vmess_link

# ----------------------------- argparse Actions ----------------------------- #

if args.dockerfile :
  v2ray_dockercompose()

# call DNS func
if args.dns :
  dnsselect()
  
  if args.dns not in dnslist :  # list of DNS
    print(f"""List of Avalible DNS :
  {green}google
  cloudflare
  both : google + cloudflare
  opendns
  quad9
  adguard
  nodns{reset}""")
    sys.exit()

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

# vmess config port :
if args.port == None :
  pass
else :
  PORT = args.port

# make config with defined parameters
if args.protocol or args.generate :
  vmess_make()
  if args.protocol not in protocol_list:  # list of outband protocols
    print(f"""{yellow}! use --protocol to set method{reset}
List of outband methods :
  {green}freedom
  blackhole
  both : freedom + blackhole{reset}""")
    sys.exit()
  else:
    uuid_port()

# simple vmess configuration gen
if args.vmess:
  vmess_simple()

# Run Service :
if args.dockerup:
  run_docker()

if args.link:
  if args.generate is None or args.protocol is None:
    parser.error('--generate and --protocol are required')
  else:
    print(vmess_link_generator(args.linkname))