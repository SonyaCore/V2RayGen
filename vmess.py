
import base64
import os
x = ("""vmess://\{\"add\":\"$IP\", \
\"aid\":\"0\", \
\"host\":\"\", \
\"id\":\"$UUID\", \
\"net\":\"ws\", \
\"path\":\"/graphql\", \
\"port\":\"$PORT\", \
\"ps\":\"v2ray\", \
\"tls\":\"\", \
\"type\":\"none\", \
\"v\":\"2\"\}""")

#os.system(f'echo {base64.encode(x)}')

#prelink = 'vmess://'
#link = '{' + f"add:{IP}, aid:0, host:, id:, net:ws, path:/graphql, port:{PORT}, ps:{v2ray}, tls:, type:none, v:2" + '}'
#print(link)

import uuid
myuuid = uuid.uuid4()


def vmess_link_generator():
  "generate vmess link"
  vmess_config_name = 'v2ray'
  prelink = 'vmess://'

  raw_link = bytes('{' + f"add:s, aid:0, host:, id:{myuuid}, net:ws, path:/graphql, port:s, ps:v2ray, tls:, type:none, v:2" + '}',\
  encoding='ascii')
  link = base64.b64encode(raw_link) # encode raw link
  
  final = prelink + \
  str(link.decode('utf-8')) # concatenate prelink with rawlink

  print(final)

vmess_link_generator()