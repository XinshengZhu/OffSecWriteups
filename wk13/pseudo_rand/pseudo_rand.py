import ctypes
from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./pseudo_rand"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1514
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

libc = ctypes.CDLL("libc.so.6")
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value + 0x19 + 1))
libc.rand.restype = ctypes.c_int
random_number = libc.rand()

p.sendline(str(random_number).encode())
log.info(f"Sending random number: {random_number}")

p.interactive()

# flag{l00ks_l1k3_th4t_seed_w4snt_gr34t!_42aae8e6c9c89860}
