from pwn import *
from math import log2

goal = 0x7fffffff
n = int(log2(goal) + 1)

CHALLENGE = "./disks_game"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1261
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b"\nHow many disks do you want to start with?\n> ").decode())
p.sendline(str(n).encode())
log.info(f"Sending result in base 10: {n}")
print(p.recvall().decode())
p.interactive()

# flag{r3curs1v3_funct10ns_4nd_3xp0n3nt14l_gr0wth!_1868aeed111bed40}
