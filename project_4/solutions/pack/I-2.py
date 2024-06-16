#!/usr/bin/python3
from pwn import *

import os
import random
import time

def get_secret():
    random.seed(int(time.time()))
    secret = ''.join(chr(48 + random.randint(0, 126 - 48 + 1)) for _ in range(16))
    return secret

def get_new_secret():
    return os.popen("./get_secret").read().strip()

context(arch = 'x86_64', os = 'linux')

r = remote('140.113.24.241', 30171, level="error")
secret = get_new_secret()

r.recvuntil(b"Please enter the secret: \n")
r.sendline(secret.encode())
r.recvline()
print(r.recvline().decode(), end="")
