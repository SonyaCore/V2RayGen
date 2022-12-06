#!/usr/bin/env python3

# XRay Config Generator
# ------------------------------------------
#   Author    : mar-coding
# 	Github    : https://github.com/mar-coding


import errno
import os
import re

# -------------------------------- Constants --------------------------------- #

# Name of environment file
NAME = ".env"


def create_env():
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        file_handle = os.open(NAME, flags)
    except OSError as e:
        if e.errno == errno.EEXIST:  # Failed as the file already exists.
            pass
        else:  # Something unexpected went wrong so reraise the exception.
            raise


def set_var(name: str, value: str):
    f = open(NAME, 'a')
    variables = dict()
    get_all_var(variables)
    try:
        if value.isnumeric():
            tmpStr = name + "=" + str(value) + "\n"
        else:
            tmpStr = name + "=" + "\'" + value + "\'" + "\n"
        if name not in variables:
            f.write(tmpStr)
        else:
            if value != variables[name]:
                update_entry(name, value)
    finally:
        f.close()


def update_entry(name: str, value: str):
    """
    it updated variable with name of 'name' and
    changes the value of that with 'value'
    """
    output = ""
    with open(NAME) as file:
        while (line := file.readline().rstrip()):
            try:
                if not re.search(r'\b' + name + r'\b', line):
                    output = output + line + "\n"
                else:
                    # if not value in line:
                    if value.isnumeric():
                        tmpStr = name + "=" + str(value) + "\n"
                    else:
                        tmpStr = name + "=" + "\'" + value + "\'" + "\n"
                    # else:
                    #     output = output + (line+"\n")
                    output = output + tmpStr
            except:
                pass
        set_all_var(output)


def set_all_var(values: str):
    """
    it gets '\n' separated name=value environment
    variables.
    """
    f = open(NAME, 'w')
    try:
        f.write(values)
    finally:
        f.close()


def get_all_var(values: dict):
    """
    you have to create dict and send it to 
    this method to get all environment variables. 
    """
    with open(NAME) as file:
        while (line := file.readline().rstrip()):
            try:
                key, value = line.split("=")
                values[key] = value.replace("'", "")
            except ValueError:
                pass


def reset_all_var():
    f = open(NAME, 'w')
    try:
        f.write("")
    finally:
        f.close()


if __name__ == "__main__":
    print("Its not Runnable without proper script to run it")
