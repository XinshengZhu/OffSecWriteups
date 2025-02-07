from pwn import *

CHALLENGE = "./rdp"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1272
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b"Send me the right data and I'll give you the flag!\n").decode())
msg_1 = b"\x03\x00\xff"
p.send(msg_1)
log.info(f"Sending a message to establish a connection: {msg_1}")
print(p.recvuntil(b"Connection Established!\n").decode())
msg_2 = b"\x04\x01\xff\x37"
p.send(msg_2)
log.info(f"Sending a message to communicate information: {msg_2}")
print(p.recvuntil(b"That's a nice message!\n").decode())
msg_3 = b"\x03\x02\xff"
p.send(msg_3)
log.info(f"Sending a message to disconnect: {msg_3}")
print(p.recvuntil(b"Disconnected!\n").decode())
print(p.recvall().decode())

p.interactive()

# flag{w3_r34lly_l1k3_s3r14l1z3d_d4t4!_cba709f17019650c}
