from pwn import *
from z3 import *

def find_hamming_pairs(count):
    # Create two bit vectors of size 32
    V1 = BitVec('V1', 32)
    V2 = BitVec('V2', 32)

    # Create a solver
    solver = Solver()

    # Add constraints to ensure V1 and V2 are 11-digit decimal numbers
    solver.add(V1 >= 0, V1 <= 99999999999)
    solver.add(V2 >= 0, V2 <= 99999999999)

    # Calculate the Hamming distance and add the constraint
    h = V1 ^ V2
    # Extract each bit of the XOR result
    bits = [(Extract(i, i, h) == 1,1) for i in range(32)]
    # Add the Hamming distance constraint: the number of bits set in the XOR result is equal to count
    solver.add(PbEq(bits, count))

    # Solve the problem
    if solver.check() == sat:
        model = solver.model()
        # Return found V1 and V2
        return model[V1].as_long(), model[V2].as_long()
    else:
        # Return None if no solution is found
        return None, None

hamming_distances = {
    # Node: [Hamming distance, (V1, V2)]
    3: [0x0e, (None, None)],
    1: [0x0d, (None, None)],
    4: [0x13, (None, None)],
    0: [0x12, (None, None)],
    5: [0x11, (None, None)],
    2: [0x12, (None, None)],
    7: [0x14, (None, None)],
    9: [0x0e, (None, None)],
    6: [0x0f, (None, None)],
    8: [0x13, (None, None)]
}

for node in hamming_distances:
    distance = hamming_distances[node][0]
    V1, V2 = find_hamming_pairs(distance)
    hamming_distances[node][1] = (V1, V2)

CHALLENGE = "./flips"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1262
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

for node in hamming_distances:
    distance = hamming_distances[node][0]
    V1, V2 = hamming_distances[node][1]
    print(p.recvuntil(b"> ").decode())
    p.sendline(str(V1).encode())
    print(p.recvuntil(b"> ").decode())
    p.sendline(str(V2).encode())
    log.info(f"Sending decimal numbers {V1} and {V2} whose Hamming distance in node_{node} is {distance}")

print(p.recvall().decode())
p.interactive()

# flag{th3_numb3rs_4r3_just_4_f3w_fl1pp3d_b1ts_4p4rt!_05ce3b0138b2d60a}
