# V2Ray Config Generator
# --------------------------------
# author    : SonyaCore
#	      https://github.com/SonyaCore
#

# Librarys
import sys , os
import uuid
import argparse
import base64

# UUID Generation
myuuid = uuid.uuid4()

# Config Name
configname = 'config.json'

# Return IP
IP = os.system('hostname -I | cut -d' ' -f1')

# Argument Parser
parser = argparse.ArgumentParser(prog='V2Ray Config Generator')
parser.add_argument('--generate','--gen',action='store_true',help='generate json config')
parser.add_argument('--link','--vmess-link',action='store_true',help='generate vmess link for v2ray config')
parser.add_argument('--protocol','--outband',action='store',type=str,help='set protcol for outband connection. default: [freedom]')

parser.add_argument('--port','-p',action='store' , type=int , help='set optional port for V2Ray Config. defualt: [80]' )
parser.add_argument('--dns',action='store',type=str,help='set optional dns')

docker = parser.add_argument_group('Docker')
docker.add_argument('--dockerfile', required=False , action= 'store_true',help='generate docker-compose for v2ray')
docker.add_argument('--start', required=False , action= 'store_true',help='start v2ray docker-compose in system')

opt = parser.add_argument_group('info')
opt.add_argument('--version','-v', action='version', version='%(prog)s 0.2')

# Arg Parse
args = parser.parse_args()

# Color Format
green = '\u001b[32m'
yellow = '\u001b[33m'
blue = '\u001b[34m'
reset = '\u001b[0m'


def dnsselect():
  "DNS Selection"
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

def make():
  "Make Json Config"
  
  global protocol_list
  protocol_list = ['freedom','blackhole','both']
    
  # Config Selection
  if args.protocol == 'freedom' or None:
    with open(configname,'w') as txt :
      txt.write(vmess_config() \
      + freedom() \
      + '\n  ]\n }')
      
      txt.close
  if args.protocol == 'both':
    with open(configname,'w') as txt :
      txt.write(vmess_config() \
      + freedom() \
      +',\n' \
      + blackhole() + '\n  ]\n }')
      
      txt.close

def vmess_config():
  "vmess JSON Config File"
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
""" % (dns,PORT,myuuid)
  return data

def freedom():
  "Append freedom protocol to JSON config"

  freedom = """    {
      "protocol": "freedom",
      "settings": {}
    }"""

  return freedom

def blackhole():
  "Append blackhole protocol to JSON config"

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

def v2ray_dockercompose():
  "Docker compose for v2ray core"
  data = """version: '3'
services:
  v2ray:
    image: v2fly/v2fly-core
    restart: always
    network_mode: host
    environment:
      - V2RAY_VMESS_AEAD_FORCED=false
    volumes:
        - ./%s:/etc/v2ray/config.json:ro""" % (configname)
  with open('docker-compose.yml','w') as txt :
    txt.write(data)
    txt.close()

def run_docker():
  "start v2ray docker-compose"
  if os.path.exists('/usr/bin/docker') or os.path.exists('/usr/local/bin/docker'):
    if os.path.exists('/usr/bin/docker-compose') or os.path.exists('/usr/local/bin/docker-compose'):
      os.system('docker-compose -f docker-compose.yml up -d')
    else:
        os.system('curl -SL https://github.com/docker/compose/releases/download/v2.11.1/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose \
        chmod +x /usr/local/bin/docker-compose')
        os.system('sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose')
  else :
    # install docker if docker are not installed
    os.system('curl https://get.docker.com | sudo sh')

def vmess_link_generator():
  "generate vmess link"
  vmess_config_name = 'v2ray'
  prelink = 'vmess://'

  raw_link = bytes('{' + 
f"add:{IP},\
aid:0,\
host:,\
id:{myuuid},\
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

###################### Argument Call ######################

if args.dockerfile :
  print('! Creating v2ray Docker-Compose with this configuration')
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


# V2ray Service Port :
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
    print('UUID: ' + blue + str(myuuid) + reset)
    print(PORT)

# Run Service :
if args.start:
  run_docker()

if args.link:
  if args.generate is None or args.protocol is None:
    parser.error('--generate and --protocol are required')
  else:
    print(yellow + '! use below link for you v2ray client' + reset)
    print(vmess_link_generator())

  # try:
  #   # List of Protocols
  #   protocol = []
  #   protocol.append('freedom')
  #   protocol.append('freedom + blackhole')

  #   # Append Number to List For Method Selection
  #   pnumber = 1
  #   for method in protocol:
  #       print(f'{pnumber}. {method}')
  #       pnumber += 1
    
    # except ValueError:
    # print('enter a number')
    # exit(1)

  # # Config Selection
  # if 1 <= selectconfig < pnumber:
  #   with open(configname,'w') as txt :
  #     txt.write(configfile() \
  #     + freedom() \
  #     + '\n  ]\n }')
      
  #     txt.close
  # if 2 <= selectconfig < pnumber:
  #   with open(configname,'w') as txt :
  #     txt.write(configfile() \
  #     + freedom() \
  #     +',\n' \
  #     + blackhole() + '\n  ]\n }')
      
  #     txt.close
