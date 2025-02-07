from functools import reduce
from operator import xor
from pwn import remote, log

URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1513
NETID = b"xz4344"

p = remote(URL, PORT)
p.recvuntil(b"NetID (something like abc123): ")
p.sendline(NETID)

class LFSR:
    # 32-bit Fibonacci LFSR, characteristic polynomial:
    #   x^32 + x^7 + x^5 + x^3 + x^2 + x + 1
    # Or equivalently, as a feedback polynomial:
    #   x^32 + x^31 + x^30 + x^29 + x^27 + x^25 + 1
    # Tap positions (0-indexed): 31, 30, 29, 28, 26, 24
    # Tap bits: 00000000000000000000000010101111
    def __init__(self, seed, bits=32, taps=(24, 26, 28, 29, 30, 31)):
        # Convert the seed to bits
        self.state = self.int_to_bits(seed)
        self.taps = taps
        self.tap_bits = [1 if i in taps else 0 for i in range(bits)]

    @classmethod
    def bits_to_int(cls, bits):
        b = 0
        for bit in bits:
            b = b << 1 | bit
        return b

    @classmethod
    def int_to_bits(cls, n, bits=32):
        return list(map(int,bin(n)[2:].zfill(bits)))

    def get_bit(self):
        out_bit = self.state[-1]
        # Compute the new state bit: XOR the tap bits
        # new_bit = reduce(xor,[x & y for x,y in zip(self.state, self.taps)])
        new_bit = reduce(xor,[self.state[i] for i in self.taps])
        # Shift the state
        self.state = [new_bit] + self.state[:-1]
        return out_bit

    def get_bits(self, n):
        return [self.get_bit() for _ in range(n)]

    def get_int(self, n):
        bits = self.get_bits(n)
        return self.bits_to_int(bits)

    def get_byte(self):
        return self.get_int(8)

    def get_bytes(self, n):
        return [self.get_byte() for _ in range(n)]

    def __str__(self):
        state_str = ''.join(map(str,self.state))
        taps_str = str(self.taps)
        return f"LFSR:\n  Taps:  {taps_str}\n  State: {state_str}"
    
# Unicode animals: cow, pig, deer, sheep, chicken, dog, cat, horse
animals = ['🐄', '🐖', '🦌', '🐑', '🦃', '🐕', '🐈', '🐴']
# Unicode field elements: grass, tree, bush, rock, water, wood, droplet, green
fields = ['🌱', '🌳', '🌿', '🪨', '🟦', '🟫', '💧', '🟩']

# Receive the Galois field
print(p.recvuntil(b"Here's a happy little Galois field:\n").decode())
galois = ""
for _ in range(10):
    line = p.recvline().decode().strip()
    for i in range(0, 10):
        galois += line[i]
log.info(f"Receiving Galios field: {galois}")

# Derive the seed
seed = ""
for i in range(8):
    if galois[i] in animals:
        seed += '1'
        seed += format(animals.index(galois[i]), '03b')
    elif galois[i] in fields:
        seed += '0'
        seed += format(fields.index(galois[i]), '03b')
seed = int(seed[::-1], 2)
log.info(f"Calculating seed: {seed}")

# Synchronize the LFSR
lfsr = LFSR(seed)
for _ in range(100):
    lfsr.get_int(1)
    lfsr.get_int(3)

# Receive the encrypted flag
print(p.recvuntil(b"Here's the encrypted flag:\n").decode())
encrypted_flag = p.recvline().decode().strip()
log.info(f"Receiving encrypted flag: {encrypted_flag}")

# Decrypt the flag
encrypted_flag_chars = [int(encrypted_flag[i:i+2], 16) for i in range(0, len(encrypted_flag), 2)]
decrypted_flag = ""
for encrypted_flag_char in encrypted_flag_chars:
    decrypted_flag += chr(encrypted_flag_char ^ lfsr.get_byte())
log.info(f"Decrypting flag: {decrypted_flag}")

p.interactive()

# flag{v3ry_ps3ud0_not_so_r4nd0m!_1b853fd035c1f885}
