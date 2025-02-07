from pwn import *

CHALLENGE = "./stripped"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1270
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b"\nHey friend, can you tell me your favorite fruit? ").decode())
fruit = "Golana Melon"
p.sendline(fruit.encode())
log.info(f"Sending fruit: {fruit}")
print(p.recvuntil(b"\nAny idea where to get the flag? ").decode())
filename = "flag.txt"
p.sendline(filename.encode())
log.info(f"Sending filename: {filename}")
print(p.recvall().decode())

p.interactive()

# flag{4ll_w3_n33d_1s_kn0wl3dg3_0f_th3_sysc4ll_API!_e47a584bb03631ee}
