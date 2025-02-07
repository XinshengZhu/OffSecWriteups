import ctypes
from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./super_secure_letter"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1517
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

print(p.recvuntil(b"!\n").decode())
secured_letter = p.recvline().decode().strip()
log.info(f"Receiving secured letter: {secured_letter}")

libc = ctypes.CDLL("libc.so.6")
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value ** 2))
libc.rand.restype = ctypes.c_int

encrypted_flag = [int(secured_letter[i:i+2], 16) for i in range(0, len(secured_letter), 2)]
decrypted_flag = ""
for i in range(len(encrypted_flag)):
    decrypted_flag += chr(encrypted_flag[i] ^ libc.rand() & 0xff)
log.info(f"Decrypting flag: {decrypted_flag}")

# flag{p3rh4p5_n07_50000_53cur3:(_7fa5a2182ae33a78}
