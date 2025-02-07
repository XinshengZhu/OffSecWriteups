from pwn import *

CHALLENGE = "./heterograms"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1271
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b"Send me some data to get the flag!\n").decode())

word_list = ["unforgivable", "troublemakings", "computerizably", "hydromagnetics", "flamethrowing", "copyrightable", "undiscoverably"]
globalstate = 0

for word in word_list:

    word_payload0 = b"\x00" + globalstate.to_bytes(1, byteorder='big')
    word_payload1 = b"\x01" + len(word).to_bytes(1, byteorder='big') + bytes([c - 0x61 for c in word.encode()])
    word_payload2 = b"\x02\x00"
    word_payload = word_payload0 + word_payload1 + word_payload2
    word_checksum = (~ sum(word_payload) & 0xff).to_bytes(1, byteorder='big')
    word_data = word_checksum + word_payload
    word_length = (len(word_data)).to_bytes(1, byteorder='big')
    word_message = word_length + word_data
    
    p.send(word_message)
    log.info(f"Sending message for checking word '{word}': {word_message}")

    globalstate += 1
    if globalstate == 7:
        print(p.recvuntil(b"\n").decode())
        break
    print(p.recvuntil(b"That's a nice word!\n").decode())

    erase_payload0 = b"\x00" + globalstate.to_bytes(1, byteorder='big')
    erase_payload2 = b"\x02\x02"
    erase_payload = erase_payload0 + erase_payload2
    erase_checksum = (~sum(erase_payload) & 0xff).to_bytes(1, byteorder='big')
    erase_data = erase_checksum + erase_payload
    erase_length = (len(erase_data)).to_bytes(1, byteorder='big')
    erase_message = erase_length + erase_data

    p.send(erase_message)
    log.info(f"Sending message for erasing word '{word}': {erase_message}")

    print(p.recvuntil(b"Copy that!\n").decode())

p.interactive()

# flag{s3r1aL1z3d_d4t4_and_ST4T3_m4ch1n3s_e1287c2b087ac0f2}
