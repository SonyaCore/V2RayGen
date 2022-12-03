# !/usr/bin/env python3
import sys
import subprocess
import time
import uuid
import json
import random
import string
import re
import signal

# -------------------------------- Constants --------------------------------- #

VERSION = "1.0.1"

# UUID Generation
UUID = uuid.uuid4()

# Name
NAME = "XRayAgent"

MIN_PORT = 0
MAX_PORT = 65535

# -------------------------------- Helper Function --------------------------------- #


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
    print(
        """
{0} [options]
    add , adduser           add user
    update , updateuser     update existing user
    del , deluser           delete existing user
    users , listusers       list of users
    p , port                change server side port
    h , help                get help
    v , version             get version
    q , quit                exit program
        """.format(
            exec_name[exec_name.rfind("/") + 1 :],
        )
    )


# -------------------------------- Functions --------------------------------- #


def base_error(err):
    return print(error + "ERROR : " + reset + str(err))


def reset_docker_compose():
    subprocess.run(f"docker-compose restart", shell=True, check=True)


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

    print(green + "Loaded config file: " + reset + config)


def show_version():
    print(blue + NAME + " " + VERSION)


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

# -------------------------------- Main --------------------------------- #

def create_new_user(email, id):
    with open(config, "r") as configfile:
        data = json.loads(configfile.read())
        if data["inbounds"][0]["protocol"] == "vmess":

            try:
                alterID = input("AlterID 0 to 64 : ")
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

        elif data["inbounds"][0]["protocol"] == "vless":
            user = {"id": str(id), "level": 0, "email": str(email)}
            data["inbounds"][0]["settings"]["clients"].append(user)
            print(
                "{0} uuid: {1}, email : {2}".format(
                    ("DEL user success!"), user["id"], user["email"]
                )
            )

        with open(config, "w") as file:
            json.dump(data, file, indent=2)
            # reset_docker_compose()


def del_user(index):
    with open(config, "r") as configfile:
        data = json.loads(configfile.read())
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
                f"DELETE index {green}{index}{reset} with email : {green}{useremail}{reset} ? [y/n] "
            )
            if confirm.lower() in ["y", "yes"]:
                del data["inbounds"][0]["settings"]["clients"][index]

                print((f"Index {green}{index}{reset} deleted!"))

                with open(config, "w") as file:
                    json.dump(data, file, indent=2)
                    # reset_docker_compose()
            else:
                pass


def list_clients():
    with open(config, "r") as configfile:
        data = json.loads(configfile.read())
        index = 0
        border = f"{blue}{'-'*100}{reset}"
        list = data["inbounds"][0]["settings"]["clients"]
        print(border)
        for lists in list:
            print(f"index : {green}{index}{reset}", lists)
            index += 1
        print(border)


def update_client(index):
    with open(config, "r") as configfile:
        try :
            data = json.loads(configfile.read())
             # Check if the index is not greater than the expected size:
            if index >= len(data["inbounds"][0]["settings"]["clients"]):
                base_error(f"update index out of range. use {green}users{reset} to see clients")
                return cmd
            print("Index " + green + str(index) + reset + " Selected")
            print("Leave the section empty if you don't want to modify that section")
            new_email = input("New Email : ")
            new_email = str(new_email)

            if new_email is None or new_email == "" :
                new_email =  data["inbounds"][0]["settings"]["clients"][index]["email"]
            else :
                try:
                    validate_email(new_email)
                except TypeError:
                    return cmd

            new_id = input("New Id : ")
            new_id = str(new_id)

            if new_id is None or new_id == "" :
                new_id = data["inbounds"][0]["settings"]["clients"][index]["id"]

            if data["inbounds"][0]["protocol"] == "vmess":
                try :
                    new_alterId = input("AlterID 0 to 64 : ")
                    if new_alterId == "" or None:
                        new_alterId =  data["inbounds"][0]["settings"]["clients"][index]["alterId"]
                    new_alterId = int(new_alterId)
                    if new_alterId > 64:
                        base_error("alterID cannot be larger than 64")
                        return cmd
                    else :
                        data["inbounds"][0]["settings"]["clients"][index]["alterId"] = new_alterId
                except ValueError:
                    base_error("alterID must be a integer value")
                    return cmd


            data["inbounds"][0]["settings"]["clients"][index]["email"] = new_email
            data["inbounds"][0]["settings"]["clients"][index]["id"] = new_id

            with open(config, "w") as file:
                    json.dump(data, file, indent=2)
                    # reset_docker_compose()
                    print("index : " + green + str(index) + reset + " Updated")

        except ValueError as e :
        # if the user ID is not an integer, show an error message
            base_error("updateuser" + "require integer value")
            return cmd


def change_server_port(port):
    try:
        validate_port(port)
    except TypeError:
        return cmd

    with open(config, "r") as configfile:
        data = json.loads(configfile.read())
        configport = data["inbounds"][0]["port"]
        data["inbounds"][0]["port"] = port

        confirm = input(
            f"Change PORT {green}{configport}{reset} to {green}{port}{reset} ? [y/n] "
        )
        if confirm.lower() in ["y", "yes"]:
            with open(config, "w") as file:
                json.dump(data, file, indent=2)
                # reset_docker_compose()
                print(f"Server Side PORT changed to {port}")
        else:
            pass

# -------------------------------- Shell Parser --------------------------------- #

## BANNER
banner()

## LOAD CONFIGURATION
load_config()

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
    "listusers": list_clients,
    "users": list_clients,
    "adduser": create_new_user,
    "add": create_new_user,
    "updateuser": update_client,
    "update": update_client,
    "deluser": del_user,
    "del": del_user,
    "p": change_server_port,
    "port": change_server_port,
}

while True:
    ## shell input
    cmd = input(shell).lower()
    options = cmd.split()

    # SHELL ARGS
    ##############################################################
    try:
        # check if the command is "h" or "help"
        if cmd in ["h", "help"]:
            # call the "help" command
            commands["help"]()

        # check if the command is "v" or "version"
        elif cmd in ["v", "version"]:
            # call the "version" command
            commands["version"]()

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
            # print a message to inform the user that a user is being added
            print(green + "! adding user" + reset)
            print(green + "! leave empty for random" + reset)

            # prompt the user for an email address
            email = input("Email : ")

            # if the email address is empty, generate a random email address
            if email == "":
                email = random_email()

            # prompt the user for an ID
            id = input("ID : ")

            # if the ID is empty, generate a random ID
            if id == "":
                id = UUID

            # call the "adduser" command with the email address and ID
            commands["adduser"](email, id)

        ## Value based ARGS

        # check if the command is "update" or "updateuser"
        if "updateuser" or "update" :
            try :
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
                    base_error("del" + "require integer value")

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
                base_error("del" + "require integer value")

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
    except IndexError:
        cmd

    ###############################################################