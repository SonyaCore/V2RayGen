# !/usr/bin/env python3

# XRay Agent
# ------------------------------------------
#   Author    : SonyaCore
# 	Github    : https://github.com/SonyaCore
#   Licence   : https://www.gnu.org/licenses/gpl-3.0.en.html

import os
import sys
import subprocess
import time
import uuid
import json
import random
import string
import re
import signal
import base64
import socket
import platform
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from http.client import RemoteDisconnected
from binascii import Error

# -------------------------------- Constants --------------------------------- #

VERSION = "1.0.4"

# UUID Generation
UUID = uuid.uuid4()

# Name
NAME = "XRayAgent"

MIN_PORT = 0
MAX_PORT = 65535

IPTABLE = "/sbin/iptables"

# -------------------------------- Help --------------------------------- #

def signal_handler(sig, frame):
    print(error + "\nKeyboardInterrupt!")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

# Banner
def banner(t=0.0005):
    data = f"""{green}
__   _______                                      _   
\ \ / /  __ \               /\                   | |  
 \ V /| |__) |__ _ _   _   /  \   __ _  ___ _ __ | |_ 
  > < |  _  // _` | | | | / /\ \ / _` |/ _ \ '_ \| __|
 / . \| | \ \ (_| | |_| |/ ____ \ (_| |  __/ | | | |_ 
/_/ \_\_|  \_\__,_|\__, /_/    \_\__, |\___|_| |_|\__|
                    __/ |         __/ |               
                   |___/         |___/                

{reset}"""
    for char in data:
        sys.stdout.write(char)
        time.sleep(t)
    sys.stdout.write("\n")


def help():
    exec_name = sys.argv[0]
    help_message = (
        "{0} [options]\n"
        "    {color}USER Management :\n{res}"
        "    {add:<40} Add user\n"
        "    {update:<40} Update existing user\n"
        "    {delete:<40} Delete existing user\n"
        "    {users:<40} List of users\n"
        "\n"
        "    {color}IPTables :\n{res}"
        "    {deltable:<40} Delete rules on server-side port\n"
        "    {cil:<40} Add IP limitations on server-side port\n"
        "\n"
        "    {p:<40} Change server side port\n"
        "    {h:<40} Get help\n"
        "    {v:<40} Get version\n"
        "    {q:<40} Exit program\n"
    ).format(
        exec_name[exec_name.rfind("/") + 1 :],
        add="add, adduser",
        update="update, updateuser",
        delete="del, deluser",
        users="users, listusers",
        deltable="deliptables, deleteiptables",
        cil="climit , conlimit",
        p="p, port",
        h="h, help",
        v="v, version",
        q="q, quit",
        color= blue,
        res = reset,
    )
    print(help_message)


# -------------------------------- Helper Functions --------------------------------- #

def base_error(err):
    return print(error + "ERROR : " + reset + str(err))


def warn(msg):
    return yellow + str(msg) + reset


def info(msg):
    return green + str(msg) + reset


def docker_compose_state():
    global DOCKER_COMPOSE, DOCKER_COMPOSE_IS_UP
    if os.path.exists("/usr/bin/docker-compose") or os.path.exists(
        "/usr/local/bin/docker-compose"
    ):
        DOCKER_COMPOSE = True
        DOCKER_COMPOSE_IS_UP = green + "ON"
    else:
        DOCKER_COMPOSE = False
        DOCKER_COMPOSE_IS_UP = error + "OFF"

    print(green + f"Docker Compose : {DOCKER_COMPOSE_IS_UP}" + reset)


def reset_docker_compose():
    subprocess.run(
        f"docker-compose restart",
        shell=True,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def load_config():
    global config
    try:
        config = sys.argv[1]
    except IndexError:
        config = "config.json"
    try:
        with open(config, "r") as configfile:
            configfile.read()
    except FileNotFoundError:
        sys.exit(error + "Could not load config file: " + reset + config)

    print(green + "Loaded Config : " + reset + config)


def check_permissions(path: str) -> bool:
    read_write = os.access(path, os.R_OK | os.W_OK)
    if read_write == True:
        pass
    else:
        sys.exit(base_error(f"Permission denied: '{path}'"))


def read_config(config):
    with open(config, "r") as configfile:
        return json.loads(configfile.read())

def read_port(config):
    data = read_config(config)
    port = data["inbounds"][0]["port"]
    return port

def save_config(config, data):
    with open(config, "w") as file:
        json.dump(data, file, indent=2)

        if DOCKER_COMPOSE == True:
            reset_docker_compose()


def read_protocol(config):
    data = read_config(config)
    protocol = data["inbounds"][0]["protocol"]
    port = data["inbounds"][0]["port"]
    print(green + "Protocol : " + reset + protocol)
    print(green + "PORT : " + reset + str(port))


def show_version():
    print(blue + NAME + " " + VERSION)


def clear_screen():
    if os.name == "posix":
        os.system("clear")
    elif os.name == "nt":
        os.system("cls")


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


# -------------------------------- Colors --------------------------------- #

green = "\u001b[32m"
yellow = "\u001b[33m"
blue = "\u001b[34m"
error = "\u001b[31m"
reset = "\u001b[0m"

# -------------------------------- Functions --------------------------------- #

def validate_email(email):
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    if re.fullmatch(regex, email):
        pass
    else:
        base_error(" Please enter a valid email address")
        raise TypeError


def random_email():
    domains = ["yandex", "protonmail", "gmail", "outlook", "yahoo", "icloud"]
    email = "@{}.com".format(random.choice(domains))
    return "".join(random.sample(string.ascii_letters + string.digits, 8)) + email


def validate_port(port):
    if port < MIN_PORT or port > MAX_PORT:
        base_error("Port number must be between %d and %d." % (MIN_PORT, MAX_PORT))
        raise TypeError
    else:
        pass


def port_is_use(port):
    """
    check if port is used for a given port
    """
    state = False
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stream.settimeout(2)
    try:
        if stream.connect_ex(("127.0.0.1", int(port))) == 0:
            state = True
        else:
            state = False
    finally:
        stream.close()
    return state

def permission_check():
    global ROOT
    if os.geteuid() != 0:
        print("You need to have root privileges to run this command.")
        ROOT = False
    else :
        ROOT = True
        pass
    return ROOT

def byte_conv(bytes, precision=1):

    if bytes < 0:
        raise ValueError(base_error("bytes can't be smaller than 0"))
 
    byte_unit = 1024.
 
    bytes = float(bytes)
    unit = 'bytes'
 
    if (bytes / byte_unit) >= 1:
        bytes /= byte_unit
        unit = 'KB'
 
    if (bytes / byte_unit) >= 1:
        bytes /= byte_unit
        unit = 'MB'
 
    if (bytes / byte_unit) >= 1:
        bytes /= byte_unit
        unit = 'GB'
 
    if (bytes / byte_unit) >= 1:
        bytes /= byte_unit
        unit = 'TB'

    bytes = round(bytes, precision)


# -------------------------------- IPTables --------------------------------- #

def conlimit(num):
    port = read_port(config)
    LOWESET_CONNECTION = 3

    exec = "{} -A INPUT -p tcp --syn --dport {} -m connlimit --connlimit-above {} -j REJECT --reject-with tcp-reset".format(IPTABLE,port,num)
    if num < LOWESET_CONNECTION :
        base_error("Total Connections can't be lower than {}".format(LOWESET_CONNECTION))
        return cmd
    permission_check()
    if ROOT == True:
        confirm = input("ADD Connection LIMIT to PORT {} with {} Connections ? [y/n] ".format(port,num))
        if confirm.lower() in ["y", "yes"]:
            subprocess.run(exec,shell=True , check=True)
            print(info("Total CONNECTIONS of PORT {} set to {}").format(port,num))
        else:
            pass

def clean_iptables():
    port = read_port(config)
    exec = "{} -D {} {}"
    check_cmd = (
        "%s -nvL %s --line-number 2>/dev/null|grep -w \"%s\"|awk '{print $1}'|sort -r"
    )
    firewall_clean_cmd = "firewall-cmd --zone=public --remove-port={}/tcp --remove-port={}/udp --permanent >/dev/null 2>&1"

    permission_check()
    if ROOT == True:
        confirm = input("DELETE INPUT & OUTPUT Chain on PORT {} ? [y/n] ".format(port))
        if confirm.lower() in ["y", "yes"]:
            if "centos-8" in platform.platform():
                subprocess.run(
                    "{}-save -c > /etc/sysconfig/iptables 2>/dev/null".format(IPTABLE),
                    shell=True,
                    check=True,
                )
                subprocess.run(
                    firewall_clean_cmd.format(str(port), str(port)),
                    shell=True,
                    check=True,
                )
                subprocess.run(
                    "firewall-cmd --reload >/dev/null 2>&1", shell=True, check=True
                )
                subprocess.run(
                    "{}-restore -c < /etc/sysconfig/iptables".format(IPTABLE),
                    shell=True,
                    check=True,
                )
            input_chain = os.popen(
                check_cmd % (IPTABLE, "INPUT", str(port))
            ).readlines()
            for line in input_chain:
                subprocess.run(
                    exec.format(IPTABLE, "INPUT", str(line)),
                    shell=True,
                    check=True,
                )

            output_chain = os.popen(
                check_cmd % (IPTABLE, "OUTPUT", str(port))
            ).readlines()
            for line in output_chain:
                subprocess.run(
                    exec.format(IPTABLE, "OUTPUT", str(line)),
                    shell=True,
                    check=True,
                )
            print(info("DELETED {} RULES").format(len(output_chain + input_chain)))
    else:
        pass


# -------------------------------- LINK GENERATOR --------------------------------- #

def link_generator(data, index) -> str:
    """
    Generate a link with the specified prelink and data.
    """
    read_config(config)
    id = data["inbounds"][0]["settings"]["clients"][index]["id"]

    try:
        net = data["inbounds"][0]["streamSettings"]["network"]
    except KeyError:
        net = ""
        pass

    try:
        if data["inbounds"][0]["streamSettings"]["network"] == "ws":
            try:
                path = data["inbounds"][0]["streamSettings"]["wsSettings"]["path"]
            except KeyError:
                path = ""
                pass
    except KeyError:
        pass

    port = data["inbounds"][0]["port"]

    ps = "xray"

    security = data["inbounds"][0]["streamSettings"]["security"]

    if data["inbounds"][0]["protocol"] == "vmess":
        aid = data["inbounds"][0]["settings"]["clients"][index]["alterId"]
        print(vmess_link_generator(aid, id, net, path, port, ps, security))
    elif data["inbounds"][0]["protocol"] == "vless":
        print(vless_link_generator(id, port, net, path, security, ps))
    else:
        base_error("UNSUPPORTED PROTOCOL")


def vmess_link_generator(aid, id, net, path, port, ps, tls) -> str:
    PRELINK = "vmess://"

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

    vmess_link = PRELINK + str(link.decode("utf-8"))  # concatenate prelink with rawlink

    return vmess_link


def vless_link_generator(id, port, net, path, security, name) -> str:
    PRELINK = "vless://"

    raw_link = f"{id}@{ServerIP}:{port}?path={path}&security={security}&encryption=none&type={net}#{name}"

    vless_link = PRELINK + raw_link

    return vless_link


# -------------------------------- Main --------------------------------- #


def create_user():
    data = read_config(config)
    # print a message to inform the user that a user is being added
    print(info("! ADDING User"))
    print(info("! Leave Sections Empty for Random Value"))

    # prompt the user for an email address
    email = input(warn("Email :"))

    # if the email address is empty, generate a random email address
    if email == "":
        email = random_email()

    # prompt the user for an ID
    id = input(warn("ID / UUID : "))

    # if the ID is empty, generate a random ID
    if id == "":
        id = UUID

    user = {}
    if data["inbounds"][0]["protocol"] == "vmess":

        try:
            alterID = input(warn("AlterID 0 to 64 : "))
            if alterID == "" or None:
                alterID = 0
            alterID = int(alterID)
            if alterID > 64:
                base_error("alterID cannot be larger than 64")
                return cmd
        except ValueError:
            print(base_error("alterID must be a integer value"))
            return cmd

        try:
            validate_email(email)
        except TypeError:
            return cmd

        user = {"alterId": alterID, "level": 0, "id": str(id), "email": str(email)}
        data["inbounds"][0]["settings"]["clients"].append(user)

        print(
            "{0} uuid: {1}, alterId: {2}, email : {3}".format(
                ("ADD user success!"), user["id"], user["alterId"], user["email"]
            )
        )
        link_generator(data, -1)

    elif data["inbounds"][0]["protocol"] == "vless":
        user = {"id": str(id), "level": 0, "email": str(email)}
        data["inbounds"][0]["settings"]["clients"].append(user)
        print(
            "{0} uuid: {1}, email : {2}".format(
                ("ADD user success!"), info(user["id"]), info(user["email"])
            )
        )
        link_generator(data, -1)

    save_config(config, data)


def del_user(index):
    data = read_config(config)
    if index >= len(data["inbounds"][0]["settings"]["clients"]):
        base_error(f"del index out of range. use {green}users{reset} to see clients")
        return cmd
    if (
        data["inbounds"][0]["settings"]["clients"][index]
        == data["inbounds"][0]["settings"]["clients"][0]
        or index == 0
    ):
        base_error("Can't Delete first client")
    elif index < 0:
        base_error(
            +"Please Select Proper index !"
            + "\nuse users or listusers to see index values"
        )
    else:
        useremail = data["inbounds"][0]["settings"]["clients"][index]["email"]
        confirm = input(
            f"DELETE index {info(index)} with email : {info(useremail)} ? [y/n] "
        )
        if confirm.lower() in ["y", "yes"]:
            del data["inbounds"][0]["settings"]["clients"][index]

            print((f"Index {info(index)} deleted!"))

            save_config(config, data)
        else:
            pass


def update_user(index):
    try:
        data = read_config(config)
        if index >= len(data["inbounds"][0]["settings"]["clients"]):
            base_error(
                f"del index out of range. use {green}users{reset} to see clients"
            )
            return cmd
        print("Index " + green + str(index) + reset + " Selected")
        print("Leave the section empty if you don't want to modify that section")
        new_email = input(warn("New Email : "))
        new_email = str(new_email)

        if new_email is None or new_email == "":
            new_email = data["inbounds"][0]["settings"]["clients"][index]["email"]
        else:
            try:
                validate_email(new_email)
            except TypeError:
                return cmd

        new_id = input(warn("New ID : "))
        new_id = str(new_id)

        if new_id is None or new_id == "":
            new_id = data["inbounds"][0]["settings"]["clients"][index]["id"]

        if data["inbounds"][0]["protocol"] == "vmess":
            try:
                new_alterId = input(warn("AlterID 0 to 64 : "))
                if new_alterId == "" or None:
                    new_alterId = data["inbounds"][0]["settings"]["clients"][index][
                        "alterId"
                    ]
                new_alterId = int(new_alterId)
                if new_alterId > 64:
                    base_error("alterID cannot be larger than 64")
                    return cmd
                else:
                    data["inbounds"][0]["settings"]["clients"][index][
                        "alterId"
                    ] = new_alterId
            except ValueError:
                base_error("alterID must be a integer value")
                return cmd

        data["inbounds"][0]["settings"]["clients"][index]["email"] = new_email
        data["inbounds"][0]["settings"]["clients"][index]["id"] = new_id

        save_config(config, data)
        print("Index " + info(index) + " Updated")
        link_generator(data, index)

    except ValueError as e:
        # if the user ID is not an integer, show an error message
        base_error("updateuser" + "require integer value")
        return cmd


def list_users():
    data = read_config(config)
    border = f"{blue}{'-'*100}{reset}"
    list = data["inbounds"][0]["settings"]["clients"]
    print(border)
    for index, user in enumerate(list):
        print(f"Index : {info(index)}", user)
    print(border)


def change_server_port(port):
    try:
        validate_port(port)
    except TypeError:
        return cmd

    data = read_config(config)
    configport = data["inbounds"][0]["port"]
    data["inbounds"][0]["port"] = port

    if port_is_use(port):
        print("PORT {} is being used. try another".format(green + str(port) + reset))
        return cmd
    else:
        confirm = input(f"Change PORT {warn(configport)} to {info(port)} ? [y/n] ")
        if confirm.lower() in ["y", "yes"]:
            save_config(config, data)
            print(f"Server Side PORT changed to {info(port)}")
        else:
            pass


# -------------------------------- Shell Parser --------------------------------- #

## BANNER
banner()

## LOAD CONFIGURATION
load_config()

## CHECK CONFIGURATION PERMISSIONS
check_permissions(config)

## CHECK DOCKER_COMPOSE
docker_compose_state()

## SHOW SERVER IP
try:
    ServerIP = IP()
    print(green + "IP : " + reset + ServerIP)
except RemoteDisconnected as e:
    base_error(str(e))
except URLError as e:
    base_error(str(e))

## SHOW CONFIGURATION PROTOCOL
read_protocol(config)

print()

## HELPER FUNCTION
help()

## SHELL PS
shell = green + "cmd > : " + reset

### COMMAND MAPPER
commands = {
    "h": help,
    "help": help,
    "v": show_version,
    "version": show_version,
    "q": quit,
    "quit": quit,
    "listusers": list_users,
    "users": list_users,
    "adduser": create_user,
    "add": create_user,
    "updateuser": update_user,
    "update": update_user,
    "deluser": del_user,
    "del": del_user,
    "p": change_server_port,
    "port": change_server_port,
    "clear": clear_screen,
    "c": clear_screen,
    "deleteiptables": clean_iptables,
    "deliptables": clean_iptables,
    "conlimit": conlimit,
    "climit": conlimit,
}

while True:
    ## shell input
    try:
        cmd = input(shell).lower()
        options = cmd.split()
    except EOFError:
        print(error + "\nKeyboardInterrupt!")
        exit(1)

    # SHELL ARGS
    ###########################################################################
    try:
        # check if the command is "h" or "help"
        if cmd in ["h", "help"]:
            # call the "help" command
            commands["help"]()

        # check if the command is "v" or "version"
        elif cmd in ["v", "version"]:
            # call the "version" command
            commands["version"]()

        # check if the command is "c" or "clear"
        elif cmd in ["c", "clear"]:
            # call the "version" command
            commands["clear"]()

        # check if the command is "q" or "quit"
        elif cmd in ["q", "quit"]:
            # call the "q" command
            commands["q"]()

        # check if the command is "listusers" or "users"
        elif cmd in ["listusers", "users"]:
            # call the "listusers" command
            commands["listusers"]()

        # check if the command is "adduser" or "add"
        elif cmd in ["adduser", "add"]:
            # call the "adduser" command with the email address and ID
            commands["adduser"]()

        # check if the command is "deleteiptable" or "diptable"
        elif cmd in ["deleteiptables", "deliptables"]:
            # call the "adduser" command with the email address and ID
            commands["deleteiptables"]()

        ## Value based ARGS

        # check if the command is "update" or "updateuser"
        if "updateuser" or "update":
            try:
                if options[0] in ["update", "updateuser"]:
                    # Initialize a counter variable
                    i = 1
                    # iterate over the options list
                    while i < len(options):
                        # get the ID of the user to delete
                        id = options[i]
                        # call the "updateuser" command with the user ID
                        commands["updateuser"](int(id))
                        i += 1
            except ValueError:
                # if the user ID is not an integer, show an error message
                base_error("update " + "require integer value")

        # check if the command is "deluser" or "del"
        if "deluser" or "del" in cmd:
            try:
                if options[0] in ["del", "deluser"]:
                    # Initialize a counter variable
                    i = 1
                    # iterate over the options list
                    while i < len(options):
                        # get the ID of the user to delete
                        id = options[i]
                        # call the "deluser" command with the user ID
                        commands["deluser"](int(id))
                        i += 1
            except ValueError:
                # if the user ID is not an integer, show an error message
                base_error("del " + "require integer value")

        # check if the command contains "port" or "p"
        if "port" or "p" in cmd:
            try:
                # check if the first option is "port" or "p"
                if options[0] in ["port", "p"]:
                    # get the port number from the options
                    port = options[1]
                    # call the "port" command with the port number
                    commands["port"](int(port))
            except ValueError:
                # if the PORT is not an integer, show an error message
                base_error("port " + "require integer value")

         # check if the command contains "conlimit" or "climit"
        if "conlimit" or "climit" in cmd:
            try:
                # check if the first option is "port" or "p"
                if options[0] in ["conlimit", "climit"]:
                    # get the max connection number from the options
                    num = options[1]
                    # call the "port" command with the port number
                    commands["conlimit"](int(num))
            except ValueError:
                # if the num is not an integer, show an error message
                base_error("conlimit " + "require integer value")       
    except IndexError:
        cmd
    ###########################################################################
