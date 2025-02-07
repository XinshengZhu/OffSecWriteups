import binascii
import gmpy2
from pwn import *

URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1516
NETID = b"xz4344"

p = remote(URL, PORT)
p.recvuntil(b"NetID (something like abc123): ")
p.sendline(NETID)

print(p.recvuntil(b"e1 = ").decode())
e1 = int(p.recvline().decode())
log.info(f"Receiving e1: {e1}")
print(p.recvuntil(b"n1 = ").decode())
n1 = int(p.recvline().decode())
log.info(f"Receiving n1: {n1}")
print(p.recvuntil(b"c1 = ").decode())
c1 = int(p.recvline().decode())
log.info(f"Receiving c1: {c1}")
print(p.recvuntil(b"e2 = ").decode())
e2 = int(p.recvline().decode())
log.info(f"Receiving e2: {e2}")
print(p.recvuntil(b"n2 = ").decode())
n2 = int(p.recvline().decode())
log.info(f"Receiving n2: {n2}")
print(p.recvuntil(b"c2 = ").decode())
c2 = int(p.recvline().decode())
log.info(f"Receiving c2: {c2}")

print(p.recvuntil(b"?\n").decode())
if n1 == n2:
    result = gmpy2.invert(e1, e2)
    a = result
    b = (1 - a * e1) // e2
    m = (gmpy2.powmod(c1, a, n1) * gmpy2.powmod(c2, b, n2)) % n1
    plaintext = binascii.unhexlify(hex(m)[2:]).decode()
    log.info(f"Decrypting plaintext: {plaintext}")

# flag{n1c3_j0b_br34k1ng_T3xtB00k_RSA!_e31a072c43777142}
