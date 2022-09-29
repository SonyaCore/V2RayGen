#!/usr/bin/env python3

# V2Ray Config Generator
# --------------------------------
# author    : SonyaCore
#	      https://github.com/SonyaCore


# Librarys
import os
import uuid
import argparse
import base64
import socket   


# -------------------------------- Constants --------------------------------- #

# UUID Generation
UUID = uuid.uuid4()

# Config Name
CONFIGNAME = 'config.json'

# -------------------------------- Argument Parser --------------------------------- #

formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=64)
parser = argparse.ArgumentParser(prog='V2Ray Config Generator',formatter_class=formatter)
gp = parser.add_mutually_exclusive_group()
gp.add_argument('--simple','-s',action='store_true',
help='generate simple vmess config and starting it with docker')

vmess = parser.add_argument_group('VMess')
vmess.add_argument('--generate','--gen',action='store_true',

help='generate vmess json config')
vmess.add_argument('--link','--vmess-link',action='store_true',
help='generate vmess link for v2ray config')

vmess.add_argument('--protocol','--outband',action='store',type=str,
help='set protcol for outband connection. default: [freedom]')

vmess.add_argument('--port','-p',action='store' , type=int ,
help='set optional port for V2Ray Config. defualt: [80]' )

vmess.add_argument('--dns',action='store',type=str,
help='set optional dns')

docker = parser.add_argument_group('Docker')
docker.add_argument('--dockerfile', required=False , action= 'store_true',
help='generate docker-compose for v2ray')

docker.add_argument('--start', required=False , action= 'store_true',
help='start v2ray docker-compose in system')

opt = parser.add_argument_group('info')
opt.add_argument('--version','-v', action='version', version='%(prog)s 0.2')

# Arg Parse
args = parser.parse_args()

# ------------------------------ Miscellaneous ------------------------------- #

# Color Format
green = '\u001b[32m'
yellow = '\u001b[33m'
blue = '\u001b[34m'
reset = '\u001b[0m'

# Return IP
def IP():
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

def dnsselect():
  '''
  DNS Selection
  '''
  global both , google , cloudflare , NODNS
  global dnslist
  dnslist = ['both','google','cloudflare','nodns']

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
  NODNS = ''

# -------------------------------- VMess JSON --------------------------------- #

def make():
  '''
  Make JSON config
  '''
  
  global protocol_list
  protocol_list = ['freedom','blackhole','both']
    
  # config method
  if args.protocol == 'freedom' or None:
    with open(CONFIGNAME,'w') as txt :
      txt.write(vmess_config() \
      + freedom() \
      + '\n  ]\n }')

      txt.close

  if args.protocol == 'blackhole':
    with open(CONFIGNAME,'w') as txt :
      txt.write(vmess_config() \
      + blackhole() \
      + '\n  ]\n }')

  if args.protocol == 'both':
    with open(CONFIGNAME,'w') as txt :
      txt.write(vmess_config() \
      + freedom() \
      +',\n' \
      + blackhole() \
      + '\n  ]\n }')
      
      txt.close

def vmess_config() -> str:
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
""" % (dns,PORT,UUID)
  return data

def freedom() -> str:
  '''
  Append freedom protocol to JSON config
  '''

  freedom = """    {
      "protocol": "freedom",
      "settings": {}
    }"""

  return freedom

def blackhole() -> str:
  '''
  Append blackhole protocol to JSON config
  '''

  blackhole = """    {
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      },
      "tag": "block"
    }"""
  return blackhole

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

  print('! Creating v2ray Docker-Compose with this configuration')
  with open('docker-compose.yml','w') as txt :
    txt.write(data)
    txt.close()

def run_docker():
  '''
  start v2ray docker-compose
  '''

  # check if docker exist 
  if os.path.exists('/usr/bin/docker') or os.path.exists('/usr/local/bin/docker'):
    # check if docker-compose exist
    if os.path.exists('/usr/bin/docker-compose') or os.path.exists('/usr/local/bin/docker-compose'):
      os.system('docker-compose -f docker-compose.yml up -d')
    else:
        os.system('curl -SL https://github.com/docker/compose/releases/download/v2.11.1/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose \
        chmod +x /usr/local/bin/docker-compose')
        os.system('sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose')
  else :
    # install docker if docker are not installed
    os.system('curl https://get.docker.com | sudo sh')


# ------------------------------ VMess Link Gen ------------------------------- #

def vmess_link_generator() -> str:
  '''
  generate vmess link
  '''

  vmess_config_name = 'v2ray'
  prelink = 'vmess://'
  print(yellow + '! use below link for you v2ray client' + reset)
  raw_link = bytes('{' + 
f"add:{IP},\
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

# Call DNS
if args.dns :
  dnsselect()
  
  if args.dns not in dnslist :  # list of DNS
    print("""List of Avalible DNS :
  google
  cloudflare
  both : google + cloudflare
  nodns""")
# Set To NODNS
else:
  dns = ''

# DNS Selection
if args.dns == 'both':
  dns = both
if args.dns == 'google':
  dns = google
if args.dns == 'cloudflare':
  dns = cloudflare
if args.dns == 'nodns':
  dns = NODNS


# vmess config port :
if args.port == None :
  PORT = 80
else :
  PORT = args.port

# MakeConfig
if args.protocol or args.generate :
  make()
  if args.protocol not in protocol_list:  # list of outband protocols
    print(f"""{yellow}! use --protocol to set method{reset}
\nList of methods :
  {green}freedom
  blackhole
  both : freedom + blackhole{reset}""")
  else:
    print('UUID: ' + blue + str(UUID) + reset)
    print(PORT)

# Run Service :
if args.start:
  run_docker()

if args.link:
  if args.generate is None or args.protocol is None:
    parser.error('--generate and --protocol are required')
  else:
    print(vmess_link_generator())

if args.simple:
  """ simple configuration will setup vmess config with configuration :\n
  protocol freedom\n
  dns google\n
  port 80\n
  docker compose\n
  run docker compose install docker if docker bin not exist\n
  vmess link generate
  """
  args.protocol = 'freedom'
  dnsselect()
  dns = google
  make()
  v2ray_dockercompose()
  run_docker()
  print(vmess_link_generator())