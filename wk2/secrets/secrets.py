from pwn import *
import string

# context.log_level = "DEBUG"

CHALLENGE = "secrets"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1254
NETID = b"xz4344"

def is_printable_ascii(byte):
    return chr(byte) in string.printable

secret = b'\xa0\x87\x9a\x86\x8f\x8c\x9b'
for key in range(256):
    message = bytearray()
    for byte in secret:
        message.append(byte ^ key)
    
    if all(is_printable_ascii(b) for b in message):
        log.info(f"The guessed key is {key} and the corresponding message after XOR operation is {message.decode('ascii')}")

        p = remote(URL, PORT)
        p.recvuntil(b"NetID (something like abc123): ")
        p.sendline(NETID)
        
        print(p.recvuntil(b"> ").decode())
        p.sendline(str(key).encode())
        log.info(f"Sending key in base 10: {str(key)}")
        response = p.recvall().decode()
        print(response)

        if "flag" in response:
            p.interactive()
            break
        p.close()

# flag{4_0n3_byt3_k3y_g1v3s_4_v3ry_sm4ll_k3y_sp4c3!_addda9a18a668504}
