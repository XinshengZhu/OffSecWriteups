from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "quasar"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1250
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b"> ").decode())
mass = 0x3f5476a00
p.sendline(hex(mass).encode())
log.info(f"Sending mass in base 16: {hex(mass)}")
print(p.recvall().decode())

p.interactive()

# flag{sc4la4r_v4lu3s_h1dd3n_1n_pl41ns1ght!_fe16431cd9070ccf}
