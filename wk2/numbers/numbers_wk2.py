from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "numbers"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1255
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b": ").decode())
address1 = 0x404730
p.sendline(hex(address1).encode())
log.info(f"Sending address in base 16: {hex(address1)}")
print(p.recvuntil(b": ").decode())
size1 = "char"
p.sendline(size1.encode())
log.info(f"Sending size in string: {size1}")

print(p.recvuntil(b": ").decode())
address2 = 0x4042a0
p.sendline(hex(0x4042a0).encode())
log.info(f"Sending address in base 16: {hex(0x4042a0)}")
print(p.recvuntil(b": ").decode())
size2 = "long long"
p.sendline(size2.encode())
log.info(f"Sending size in string: {size2}")

print(p.recvuntil(b": ").decode())
address3 = 0x404730
p.sendline(hex(address3).encode())
log.info(f"Sending address in base 16: {hex(address3)}")
print(p.recvuntil(b": ").decode())
size3 = "short"
p.sendline(size3.encode())
log.info(f"Sending size in string: {size3}")

print(p.recvuntil(b": ").decode())
address4 = 0x4043c0
p.sendline(hex(address4).encode())
log.info(f"Sending address in base 16: {hex(address4)}")
print(p.recvuntil(b": ").decode())
size4 = "void*"
p.sendline(size4.encode())
log.info(f"Sending size in string: {size4}")

print(p.recvuntil(b": ").decode())
address5 = 0x4044c8
p.sendline(hex(address5).encode())
log.info(f"Sending address in base 16: {hex(address5)}")
print(p.recvuntil(b": ").decode())
size5 = "long"
p.sendline(size5.encode())
log.info(f"Sending size in string: {size5}")

p.interactive()

# flag{w1th_c4st1ng_w3_c4n_tr34t_4ny_m3m0ry_4s_4ny_d4t4_typ3!_8a3666b414881f44}
