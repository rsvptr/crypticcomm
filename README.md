# CrypticComm - Secure RSA Communication Tool

## Index

- [Overview](#overview)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
  - [Phase 1: RSA Key Generation (Group A)](#phase-1-rsa-key-generation-group-a)
  - [Phase 2: Encryption (Group B)](#phase-2-encryption-group-b)
  - [Phase 3: Decryption (Group A)](#phase-3-decryption-group-a)
- [Live Deployment](#live-deployment)
- [Source Code](#source-code)
- [Example Execution](#example-execution)
- [Important Notes](#important-notes)
- [File Structure](#file-structure)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

CrypticComm is an RSA-based tool developed to facilitate secure communication between two groups through encryption and decryption. This tool provides a step-by-step implementation of key generation, encryption, and decryption processes, allowing users to engage practically with cryptographic principles using SageMath.

Designed initially for a cryptographic mathematics module, CrypticComm highlights the following:

1. **RSA Key Generation**: Large, secure RSA keys are generated with special conditions to resist factorization attacks.
2. **Message Encryption**: Messages are converted to integers, segmented, and encrypted for secure transmission.
3. **Message Decryption**: Encrypted segments are decrypted to retrieve the original message accurately.

---

## Key Features

- **RSA Key Pair Creation**: Generates secure 300-digit prime numbers as factors of the RSA modulus.
- **Message Segmentation and Encryption**: Breaks down the message into manageable segments, encrypts each with the RSA public key.
- **Decryption of Message Segments**: Uses the private key to decrypt encrypted segments and reconstruct the original message.

---

## Prerequisites

Ensure you have the following installed to run CrypticComm:

- **SageMath**: CrypticComm uses SageMath for mathematical operations, including prime generation and modular exponentiation.
- **Python 3.6+**: For script compatibility.

---

## Installation

1. **Install SageMath** (if not already installed). Refer to the official SageMath installation guide [here](https://www.sagemath.org/download.html).
2. Clone the GitHub repository:
    ```bash
    git clone https://github.com/rsvptr/CrypticComm.git
    ```
3. Navigate to the cloned directory:
    ```bash
    cd CrypticComm
    ```

---

## Usage

CrypticComm has three primary phases:

1. **RSA Key Generation (Phase 1)**
2. **Message Encryption (Phase 2)**
3. **Message Decryption (Phase 3)**

### Phase 1: RSA Key Generation (Group A)

This phase generates RSA keys for secure communication. Group A will generate and share the public key with Group B, while keeping the private key confidential.

**Steps**:

1. Run the `key_generation.py` script:
    ```bash
    sage key_generation.py
    ```
2. The script will generate:
    - Two 300-digit primes `p` and `q`, ensuring they are distinct enough for secure factorization resistance.
    - Modulus `n = p * q`.
    - Totient `φ(n) = (p - 1) * (q - 1)`.
    - A suitable public exponent `e`.
    - Private exponent `d`.

3. **Output**:
    - Public Key `(n, e)` - to be shared with Group B.
    - Private Key `(n, d)` - to remain with Group A for decryption.

**Code Explanation**:  
The code generates secure primes using SageMath’s `random_prime` function, ensuring that `|p - q|` meets a defined threshold to avoid factorization attacks (e.g., Fermat's). It uses random seeds for reproducibility and checks the suitability of `e` to ensure it is relatively prime to `φ(n)`.

### Phase 2: Encryption (Group B)

Group B encrypts a 100-word message (segmented into 10 parts) using the public key provided by Group A.

**Steps**:

1. Modify `encryption.py` to input the public key values:
    ```python
    n = Integer(<Insert the value of n here>)
    e = Integer(<Insert the value of e here>)
    ```
2. Input your message segments (10 segments of approximately 10 words each) in the provided list in `encryption.py`.
3. Run the encryption script:
    ```bash
    sage encryption.py
    ```
4. **Output**: Each segment will be encrypted and displayed as a list of encrypted integers. Group B sends these encrypted segments back to Group A.

**Code Explanation**:  
Each message segment is converted to an integer using UTF-8 encoding, then encrypted using RSA’s modular exponentiation. The code ensures that each segment is small enough to avoid overflow relative to `n`.

### Phase 3: Decryption (Group A)

Group A decrypts the message segments received from Group B using the private key.

**Steps**:

1. Input the private key components in `decryption.py`:
    ```python
    d = Integer(<Insert value of d here>)
    n = Integer(<Insert value of n here>)
    ```
2. Input the encrypted segments received from Group B.
3. Run the decryption script:
    ```bash
    sage decryption.py
    ```
4. **Output**: The original message segments are printed, reconstructing the 100-word message from Group B.

**Code Explanation**:  
Each encrypted integer is decrypted using modular exponentiation with the private key. The decrypted numbers are converted back to text using UTF-8 encoding, reconstructing the original message content.

---

## Live Deployment

A live, interactive version of CrypticComm is available online. You can try out the tool, generate keys, encrypt messages, and decrypt messages through a user-friendly Streamlit dashboard.

**Live Demo:** [crypticom.streamlit.app](https://crypticom.streamlit.app)

---

## Source Code

The complete source code for CrypticComm is available on GitHub. Feel free to clone the repository, explore the code, and contribute improvements.

**GitHub Repository:** [https://github.com/rsvptr/CrypticComm](https://github.com/rsvptr/CrypticComm)

---

## Example Execution

### Sample Run for Phase 1 (Key Generation)
```plaintext
$ sage key_generation.py
Seed used for prime generation: 1698765432
Prime p has been generated.
Prime q has been generated.
Difference between p and q: <...>
Modulus n has been computed.
...
Public Key: (n, e)
Private Key: (d)
```

### Sample Run for Phase 2 (Encryption)
```plaintext
$ sage encryption.py
Encrypting Segments...
Segment 1: <cipher text>
Segment 2: <cipher text>
...
```

### Sample Run for Phase 3 (Decryption)
```plaintext
$ sage decryption.py
Decrypting Segments...
Segment 1: <original text>
Segment 2: <original text>
...
```

---

## Important Notes

- **Security Caution**: Although CrypticComm demonstrates RSA in a secure manner, do not use it for sensitive or production-level data encryption.
- **UTF-8 Encoding**: This tool uses UTF-8 encoding for text-to-integer conversion, which ensures compatibility for international text.
- **Key Sizes**: The use of 300-digit primes is specifically for educational purposes; for real-world applications, larger primes (e.g., 1024 or 2048 bits) are recommended.

---

## File Structure

- `key_generation.py`: Contains code for RSA key generation.
- `encryption.py`: Handles encryption of message segments.
- `decryption.py`: Manages decryption and reconstruction of the original message.
- `README.md`: This document, providing an overview and usage instructions.

---

## Troubleshooting

1. **Prime Generation Time**: Generating 300-digit primes may take time. Ensure SageMath is correctly installed and not interrupted.
2. **Message Size Limitation**: Ensure each text segment is small enough to fit the modulus constraints.
3. **Decryption Errors**: If UTF-8 decoding fails, verify the message format and integrity of the encryption steps.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

CrypticComm is designed to help users explore the principles and applications of RSA encryption practically and securely. Whether for educational purposes or as a foundation for understanding encryption methods, CrypticComm serves as an accessible, hands-on cryptographic tool.
```
