from pwn import *

CHALLENGE = "./rewards"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1263
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

city = "Brooklyn"
total = int(0xf3c7692 / 0x1337) # 51966 or 0xcafe

print(p.recvuntil(b"> ").decode())
p.sendline(b"1")
print(p.recvuntil(b"> ").decode())
p.sendline(b"Queens")
log.info(f"Add the first store: Queens")

print(p.recvuntil(b"> ").decode())
p.sendline(b"1")
print(p.recvuntil(b"> ").decode())
p.sendline(city.encode())
log.info(f"Add the second store: Brooklyn")

print(p.recvuntil(b"> ").decode())
p.sendline(b"3")
print(p.recvuntil(b"> ").decode())
p.sendline(b"Bronx")
print(p.recvuntil(b"> ").decode())
p.sendline(b"Joe")
print(p.recvuntil(b"> ").decode())
p.sendline(b"100")
print(p.recvuntil(b"> ").decode())
p.sendline(b"1")
log.info(f"Add the first customer: Bronx, Joe, 100, 1")

print(p.recvuntil(b"> ").decode())
p.sendline(b"3")
print(p.recvuntil(b"> ").decode())
p.sendline(city.encode())
print(p.recvuntil(b"> ").decode())
p.sendline(b"Sam")
print(p.recvuntil(b"> ").decode())
p.sendline(str(total).encode())
print(p.recvuntil(b"> ").decode())
p.sendline(b"2")
log.info(f"Add the second customer: Brooklyn, Sam, 51966, 2")

print(p.recvuntil(b"> ").decode())
p.sendline(b"4")

print(p.recvall().decode())
p.interactive()

# flag{n1c3_j0b_r3c0v3r1ng_th3s3_d4t4_structur3s!_f544b6a5ad768be1}
