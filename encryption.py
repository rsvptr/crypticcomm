"""
Phase 2: Encryption for Group B

This script encrypts 10 text segments using the public key (n, e) received from Group A.
- Converts text segments into integer blocks using agreed-upon encoding.
- Encrypts each block using RSA encryption.
- Prepares the encrypted segments to be sent back to Group A.
"""
print("===== Phase 2: Encryption (Group B) =====\n")

from sage.all import *
import math

# =========================
# Step 1: Receive Public Key from Group A
# =========================

# Update with actual values provided by Group A
n = Integer(<Insert the value of n here>) 
e = Integer(<Insert the value of e here>)

# Modulus bit length 
n_bit_length = n.nbits()

# =========================
# Step 2: Text-to-Integer Conversion Method
# =========================

# Define functions for text-to-integer conversion
def text_to_number(text):
    """
    Converts text to an integer using UTF-8 encoding.
    :param text: The text string to convert.
    :return: Integer representation of the text.
    """
    bytes_rep = text.encode('utf-8')
    return Integer(int.from_bytes(bytes_rep, 'big'))

def number_to_text(number):
    """
    Converts an integer back to text using UTF-8 encoding.
    :param integer: Integer representation of the text.
    :return: The original text string.
    """
    hex_str = '%x' % number
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    bytes_rep = bytes.fromhex(hex_str)
    return bytes_rep.decode('utf-8')

# =========================
# Step 3: Prepare Text Segments
# =========================

# List of 10 text segments (around 100 words total, roughly 10 words per segment)
text_segments = [
    "<Insert Segment 1 to Encrypt Here>",
    "<Insert Segment 2 to Encrypt Here>",
    "<Insert Segment 3 to Encrypt Here>",
    "<Insert Segment 4 to Encrypt Here>",
    "<Insert Segment 5 to Encrypt Here>",
    "<Insert Segment 6 to Encrypt Here>",
    "<Insert Segment 7 to Encrypt Here>",
    "<Insert Segment 8 to Encrypt Here>",
    "<Insert Segment 9 to Encrypt Here>",
    "<Insert Segment 10 to Encrypt Here>"
]

# =========================
# Step 4: Convert Text Segments to Integers and Encrypt
# =========================

print(f"Encrypting Segments...")

# Encrypt each text segment
max_block_size = (n_bit_length - 1) // 8  # in bytes

encrypted_segments = []

for idx, text in enumerate(text_segments):
    number = text_to_number(text)
    if number >= n:
        raise ValueError(f"\nSegment {idx + 1} is too large for the modulus.")
    cipher = power_mod(number, e, n)
    encrypted_segments.append(cipher)

# Transmit encrypted data back to Group 4 (Step 5)
for idx, cipher in enumerate(encrypted_segments):
    print(f"\nSegment {idx + 1}: {cipher}")

print("\nNote: UTF-8 encoding was used for text conversion.")
print("\nTo Group A: Please ensure that the same text-to-integer and integer-to-text functions are used for decryption.")