from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "cosmic_distance"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1252
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b": ").decode())
distance = 0x2cb417800
p.sendline(hex(distance).encode())
log.info(f"Sending distance in base 16: {hex(distance)}")
print(p.recvall().decode())

p.interactive()

# flag{0nly_tw3lv3_b1ll10n_l1ght_y34rs_4w4y!_4a46612a2479ae15}
