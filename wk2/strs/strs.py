from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "strs"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1253
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b"> ").decode())
str1 = 0x304a2053534d5320
str2 = 0x30382e3531393235
str3 = 0x35313533349288e2
str4 = 0x20302e32
str = p64(str1) + p64(str2) + p64(str3) + p64(str4)
p.sendline(str)
log.info(f"Sending answer in string: {str}")
print(p.recvall().decode())

p.interactive()

# flag{str1ng_c0mp4r1s0n_ch3cks_3v3ry_ch4r!_01508228bdfef84b}
