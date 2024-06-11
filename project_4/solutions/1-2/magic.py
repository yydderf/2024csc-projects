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

r = remote('140.113.24.241', 30171)
secret = get_new_secret()

print(r.recvuntil(b"Please enter the secret: \n").decode())
print(secret)
r.sendline(secret.encode())
print(r.recv(1024).decode())
