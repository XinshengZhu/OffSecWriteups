import gmpy2
from pwn import *

URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1515
NETID = b"xz4344"

p = remote(URL, PORT)
p.recvuntil(b"NetID (something like abc123): ")
p.sendline(NETID)

print(p.recvuntil(b"e = ").decode())
e = int(p.recvline().decode())
log.info(f"Receiving e: {e}")
print(p.recvuntil(b"n = ").decode())
n = int(p.recvline().decode())
log.info(f"Receiving n: {n}")
print(p.recvuntil(b"c = ").decode())
c = int(p.recvline().decode())
log.info(f"Receiving c: {c}")

print(p.recvuntil(b"?\n").decode())
result = gmpy2.iroot(c, e)
if result[1]:
    m = result[0]
    plaintext = bytes.fromhex(hex(m)[2:]).decode()
    log.info(f"Decrypting plaintext: {plaintext}")

# flag{n0_f4ct0r1ng_r3qu1r3d!_11d8753e3aa8aef6}
