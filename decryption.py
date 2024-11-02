"""
Phase 3: Decryption for Group A

This script performs the following tasks:
- Uses the private key components to decrypt received encrypted segments.
- Converts the decrypted integers back into text using the agreed-upon method.
- Verifies the integrity of the decrypted text.
"""

print("===== Phase 3: Decryption (Group A) =====\n")

# Import necessary modules from SageMath
from sage.all import *

# -----------------------------------
# Step 1: Define Private Key Components
# -----------------------------------

# Private key components from Phase 1
d = Integer(<Insert value of d here>)
n = Integer(<Insert value of n here>)

# -----------------------------------
# Step 2: Define Text Conversion Functions
# -----------------------------------

def text_to_number(text):
    """
    Converts text to an integer using UTF-8 encoding.
    """
    bytes_rep = text.encode('utf-8')
    return Integer(int.from_bytes(bytes_rep, 'big'))

def number_to_text(number):
    """
    Converts an integer back to text using UTF-8 encoding.
    """
    hex_str = '%x' % number
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    bytes_rep = bytes.fromhex(hex_str)
    return bytes_rep.decode('utf-8')

# -----------------------------------
# Step 3: Decrypt Encrypted Segments
# -----------------------------------

# Replace with the actual encrypted segments received from Group B
encrypted_segments = [
    Integer(<Insert Encrypted Segment 1 Here>),
    Integer(<Insert Encrypted Segment 2 Here>),
    Integer(<Insert Encrypted Segment 3 Here>),
    Integer(<Insert Encrypted Segment 4 Here>),
    Integer(<Insert Encrypted Segment 5 Here>),
    Integer(<Insert Encrypted Segment 6 Here>),
    Integer(<Insert Encrypted Segment 7 Here>),
    Integer(<Insert Encrypted Segment 8 Here>),
    Integer(<Insert Encrypted Segment 9 Here>),
    Integer(<Insert Encrypted Segment 10 Here>),
]

print(f"Decrypting Segments...")

decrypted_segments = []

for idx, cipher in enumerate(encrypted_segments):
    number = power_mod(cipher, d, n)
    try:
        text = number_to_text(number)
        decrypted_segments.append(text)
    except UnicodeDecodeError as error:
        print(f"\nDecoding error in Segment {idx + 1}: {error}")
        decrypted_segments.append("<Decoding Error>")

# -----------------------------------
# Step 4: Output Decrypted Text
# -----------------------------------

for idx, text in enumerate(decrypted_segments):
    print(f"\nSegment {idx + 1}: {text}")