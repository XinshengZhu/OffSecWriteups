from pwn import *

CHALLENGE = "./hand_rolled_cryptex"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1273
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b"The first round requires two inputs...\n > ").decode())
filename = "flag.txt"
p.sendline(filename.encode())
print(p.recvuntil(b"> ").decode())
mode = 0
p.send(str(mode).encode())
log.info(f"Sending filename {filename} and access mode {mode} (O_RDONLY) for the open system call")

print(p.recvuntil(b"*The first chamber opened! There is some weird carved into                   the interior...\n").decode())
fd = p.recv(4)
print(fd)
fd = u32(fd)
log.info(f"Receiving returned fd {fd} from the previous open system call")
print(p.recvuntil(b"The second phase requires a single input...\n > ").decode())
input_2 = ~ (fd ^ 0xc9) & 0xff
p.send(p8(input_2))
log.info(f"Sending character '{chr(input_2)}' with ASCII value {hex(input_2)} to satisfy the condition input_2 = ~ (fd ^ 0xc9) & 0xff")

print(p.recvuntil(b"Nice, the second chamber opened! Ok, the final level requires another single input...\n > ").decode())
input_3 = 2
p.send(p8(input_3))
log.info(f"Sending character '{chr(input_3)}' to get 1 as standard output for the later write system call")
print(p.recvall().decode())

p.interactive()

# flag{str1PP3d_B1N4R135_4r3_S0o0_much_FUN!_d13dce2c4a67a206}
