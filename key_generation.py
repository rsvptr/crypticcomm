"""
Phase 1: RSA Key Generation for Group A

This script performs the following tasks:
- Generates two large prime numbers, each with 300 digits.
- Ensures the primes are sufficiently different to prevent Fermat's factorization.
- Computes the modulus n = p * q.
- Selects a public exponent e that is relatively prime to φ(n).
- Verifies the keys by encrypting and decrypting a sample message.
- Uses random seeds for improved security.
"""
print("===== Phase 1 - RSA Key Generation (Group A) =====\n")

# Include all essential libraries from SageMath.
from sage.all import *
import time

# -----------------------------------
# Step 1: Generate Large Prime Numbers
# -----------------------------------

# Set fixed seed for reproducibility
seed_primes = int(time.time())  # Random seed value
set_random_seed(seed_primes)
print(f"Seed used for prime generation: {seed_primes}")

# Define the range for 300-digit numbers
min_limit = Integer(10**299)
max_limit = Integer(10**300 - 1)

# Function to generate a 300-digit prime number
def generate_prime():
    while True:
        candidate = random_prime(max_limit, lbound=min_limit)
        if candidate.ndigits() == 300:
            return candidate

# Generate prime p
p = generate_prime()
print("\nPrime p has been generated.")

# Generate prime q such that |p - q| is large
difference_threshold = Integer(10**200)
max_trials = 1000
trial = 0
while trial < max_trials:
    q = generate_prime()
    if abs(p - q) >= difference_threshold:
        print("\nPrime q has been generated.")
        break
    trial += 1
else:
    raise Exception("\nFailed to generate q with sufficient difference from p.")

print(f"\nDifference between p and q: {abs(p - q)}")

# -----------------------------------
# Step 2: Compute Modulus n and Totient φ(n)
# -----------------------------------

n = p * q
print("\nModulus n has been computed.")

phi_n = (p - 1) * (q - 1)
print("\nEuler's Totient φ(n) has been computed.")

# -----------------------------------
# Step 3: Select Public Exponent e
# -----------------------------------

# Set fixed seed for reproducibility
seed_exponent = int(time.time())  # Random seed value
set_random_seed(seed_exponent)
print(f"\nSeed used for public exponent generation: {seed_exponent}")

# Function to find a suitable public exponent e
def select_public_exponent(phi):
    while True:
        e_candidate = randint(2**16, phi - 1)
        if gcd(e_candidate, phi) == 1:
            return e_candidate

e = select_public_exponent(phi_n)
print("\nPublic exponent e has been selected.")

# -----------------------------------
# Step 4: Compute Private Exponent d
# -----------------------------------

d = inverse_mod(e, phi_n)
print("\nPrivate exponent d has been computed.")

# -----------------------------------
# Step 5: Verify Keys with Sample Encryption and Decryption
# -----------------------------------

def rsa_encrypt(msg, exponent, modulus):
    return power_mod(msg, exponent, modulus)

def rsa_decrypt(cipher, exponent, modulus):
    return power_mod(cipher, exponent, modulus)

# Sample message for testing
sample_msg = Integer(987654321)

# Encrypt the sample message
encrypted_msg = rsa_encrypt(sample_msg, e, n)
print("\nSample message encrypted.")

# Decrypt the encrypted message
decrypted_msg = rsa_decrypt(encrypted_msg, d, n)
print("\nEncrypted message decrypted.")

# Verify correctness
if decrypted_msg == sample_msg:
    print("\nTesting Success: Decrypted message matches the original.")
else:
    print("\nTesting Error: Decrypted message does not match the original.")

# -----------------------------------
# Step 6: Provide Public Key to Group B
# -----------------------------------

print("\nPublic Key to send to Group B:")
print(f"n = {n}")
print(f"\ne = {e}")

print("\nKeep the following Private Key confidential:")
print(f"d = {d}")

# Modulus bit length for block size calculation
n_bit_length = n.nbits()
print(f"\nModulus bit length: {n_bit_length} bits")
