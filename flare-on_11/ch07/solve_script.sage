# Define the elliptic curve parameters and the generator point
p = 0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd  # Field prime
a = 0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f  # Curve parameter a
b = 0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380  # Curve parameter b

E = EllipticCurve(GF(p), [a, b])

# Generator point G
G = E(0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8,
      0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182)

# Public key PA
PA = E(0x195b46a760ed5a425dadcab37945867056d3e1a50124fffab78651193cea7758d4d590bed4f5f62d4a291270f1dcf499,
       0x357731edebf0745d081033a668b58aaa51fa0b4fc02cd64c7e8668a016f0ec1317fcac24d8ec9f3e75167077561e2a15)

# The prime factors of the order of the curve (provided by you)
small_factors = [35809, 46027, 56369, 57301, 65063, 111659, 113111]

# The large prime factor
large_factor = 7072010737074051173701300310820071551428959987622994965153676442076542799542912293

# Total curve order is the product of these factors
curve_order = prod(small_factors) * large_factor
print(hex(curve_order))

# Step 1: Pohlig-Hellman for each small prime factor
mod_solutions = []  # To store solutions d_A mod p_i
moduli = []         # To store the moduli (the prime factors)

for q in small_factors:
    print("step1: %d"%q)
    # Define the subgroup order for each factor q
    order_q = curve_order // q
    
    # Multiply the public key and generator by the cofactor (curve_order // q)
    PA_q = order_q * PA
    G_q = order_q * G
    
    # Solve the discrete logarithm mod q using Pohlig-Hellman
    d_A_mod_q = discrete_log(PA_q, G_q, operation="+")
    
    # Store the result for the CRT
    mod_solutions.append(d_A_mod_q)
    moduli.append(q)

# Step 2: Use Chinese Remainder Theorem to combine solutions
d_A_mod_P = crt(mod_solutions, moduli)
print("d_A_mod_P = %s"%d_A_mod_P)

# Step 3: Brute force search for the full private key
# P is the product of small prime factors
P = prod(small_factors)

# Known size of the private key is 128 bits
max_d = 2^128

# Upper bound on x in the equation: d_A = x * P + d_A_mod_P
upper_bound = (max_d - d_A_mod_P) // P

# Step 4: Brute force search for the correct x
print("bruteforcing...")
for x in range(upper_bound + 1):
    # Compute candidate private key d_A
    d_A = x * P + d_A_mod_P
    
    # Check if d_A * G equals PA (i.e., check if this is the correct private key)
    if d_A * G == PA:
        print(f"Found private key: {d_A}")
        break
else:
    print("Private key not found in the search range.")

