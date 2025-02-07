import ctypes
from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./card_counting"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1511
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

def get_card(suit, rank):
    card = ""
    if suit == 0:
        card += "C"
    elif suit == 1:
        card += "D"
    elif suit == 2:
        card += "H"
    elif suit == 3:
        card += "S"
    if rank == 9:
        card += "J"
    elif rank == 10:
        card += "Q"
    elif rank == 11:
        card += "K"
    elif rank == 12:
        card += "A"
    else:
        card += str(rank + 2)
    return card

print(p.recvuntil(b"!\n").decode())

libc = ctypes.CDLL("libc.so.6")
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value))
libc.rand.restype = ctypes.c_int

for _ in range(3):
    print(p.recvuntil(b"> ").decode())
    rank = libc.rand() % 13
    suit = libc.rand() & 3
    card = get_card(suit, rank)
    p.sendline(card.encode())
    log.info(f"Sending guessed card: {card}")

p.interactive()

# flag{U_mus7_H4V3_a_cryst41_B411!!_0f5ce88c4f714520}
