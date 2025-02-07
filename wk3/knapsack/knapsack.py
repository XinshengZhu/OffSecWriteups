from pwn import *
from z3 import *

def solve_equation():
    # Create 6 integer variables
    a, b, c, d, e, f = [Int(x) for x in 'abcdef']

    # Create a Z3 solver
    solver = Solver()

    # Add constraints to the solver
    solver.add(a >= 0, b >= 0, c >= 0, d >= 0, e >= 0, f > 0)
    solver.add(0x244 * f + 0xd7 * a + 0x113 * b + 0x14f * c + 0x163 * d + 0x1a4 * e == 0x645)
    
    # Solve the problem
    if solver.check() == sat:
        model = solver.model()
        # Get the values of the variables
        a = model[a].as_long()
        b = model[b].as_long()
        c = model[c].as_long()
        d = model[d].as_long()
        e = model[e].as_long()
        f = model[f].as_long()
        # Return found values
        return a, b, c, d, e, f
    else:
        # Return None if no solution is found
        return None, None, None, None, None, None

a, b, c, d, e, f = solve_equation()
str = f"{a} - {b} - {c} - {d} - {e} - {f}"

CHALLENGE = "./knapsack"
URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 1260
NETID = b"xz4344"
LOCAL = False

if LOCAL:
    p = process(CHALLENGE)
else:
    p = remote(URL, PORT)
    p.recvuntil(b"NetID (something like abc123): ")
    p.sendline(NETID)

print(p.recvuntil(b"\tHow many of each would you like? \n\t").decode())
p.sendline(str.encode())
log.info(f"Sending result in string: {str}")
print(p.recvall().decode())
p.interactive()

# flag{1ts_n0t_t0_b4d_s0lv1ng_pr0bl3ms_w1th_Z3!_77dc3577ce036592}
