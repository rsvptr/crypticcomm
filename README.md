# CrypticComm - Interactive RSA Communication Tool

> **A simple, educational, and privacy-first app for learning and demonstrating RSA public-key cryptography in your browser.**

---

## :ledger: Index

- [Overview](#overview)
- [Key Features](#key-features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
  - [Phase 1: Key Generation](#phase-1-key-generation-group-a)
  - [Phase 2: Encryption](#phase-2-encryption-group-b)
  - [Phase 3: Decryption](#phase-3-decryption-group-a)
- [Live Demo](#live-demo)
- [Example Workflow](#example-workflow)
- [Important Notes](#important-notes)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

**CrypticComm** is a hands-on web app for experimenting with secure RSA communication between two groups (or users), designed for cryptography courses, demonstrations, and learning.  
It provides a step-by-step workflow for key generation, message encryption, and decryption—**all within your browser, powered by Python and Streamlit**.  
No SageMath, no server-side processing: all cryptography is done locally for maximum privacy and transparency.

---

## Key Features

- **One-Click RSA Key Generation**: Quickly create secure RSA key pairs at selectable bit lengths.
- **End-to-End Message Encryption**: Safely encrypt any text, with automatic UTF-8-safe segmentation for long messages.
- **Robust Decryption**: Recover segmented messages using your private key—no manual coding required.
- **OAEP Padding**: Use textbook RSA or secure OAEP padding for modern cryptographic safety.
- **File-Based Workflows**: Download and share public/private keys and encrypted messages as JSON files.
- **Privacy First**: All processing is local; nothing is sent to any backend or third party.
- **User-Friendly UI**: Clear navigation, copy-paste support, status messages, and segment-by-segment feedback.
- **Designed for Education**: Transparent, readable workflow, easy to extend or modify for demonstrations or assignments.

---

## Prerequisites

- **Python 3.8+** recommended.
- **[Streamlit](https://streamlit.io/)** (`pip install streamlit`)
- **[PyCryptodome](https://www.pycryptodome.org/)** (`pip install pycryptodome`)

Or, install both at once:
```bash
pip install streamlit pycryptodome
````

---

## Installation

1. **Clone this repository:**

   ```bash
   git clone https://github.com/rsvptr/CrypticComm.git
   cd CrypticComm
   ```

2. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

   Or manually:

   ```bash
   pip install streamlit pycryptodome
   ```

3. **Start the app locally:**

   ```bash
   streamlit run streamlit_app.py
   ```

4. Open your browser to the displayed URL (typically `http://localhost:8501`).

---

## Usage Guide

CrypticComm walks users through three main phases:

### Phase 1: Key Generation (Group A)

* Generate an RSA public/private key pair with a selectable key size.
* Download and share the public key JSON with your communication partner (Group B).
* **Keep your private key file secure!**

### Phase 2: Encryption (Group B)

* Upload or paste the public key JSON received from Group A.
* Enter your message—CrypticComm will segment and encrypt it as needed.
* Download the encrypted message file (JSON) and send it to Group A.

### Phase 3: Decryption (Group A)

* Upload or paste your private key JSON and the encrypted message file.
* Decrypts all segments and reconstructs the original message.
* Any issues (such as corrupted or truncated ciphertext) are reported segment-by-segment.

---

## Live Demo

**Try it instantly:**

[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://crypticom.streamlit.app)

---

## Example Workflow

1. **Group A (Key Generation):**

   * Click "Key Generation" in the sidebar.
   * Generate keys (2048/4096 bits recommended).
   * Download and share the public key JSON only.

2. **Group B (Encryption):**

   * Go to "Encryption".
   * Upload or paste the public key.
   * Enter your message, choose OAEP (recommended), and click Encrypt.
   * Download the encrypted JSON and send to Group A.

3. **Group A (Decryption):**

   * Go to "Decryption".
   * Upload/paste your private key and the encrypted JSON.
   * Decrypt and read the original message.

---

## Important Notes

* **Educational Use Only:** This app is for learning, demonstrations, and experiments. Do not use for real-world secrets or production!
* **All Local:** No keys, messages, or ciphertext leave your browser.
* **Key Size:** 2048 bits is a modern minimum; 4096 for higher security. Larger keys take longer to generate.
* **OAEP:** Always use OAEP padding for actual security. "Textbook" RSA is for illustration only.

---

## Troubleshooting

* **Key or message file upload fails:** Double-check the file format (must be valid JSON, as generated by CrypticComm).
* **"Segment too large for modulus":** Use a bigger key size, shorter message, or OAEP padding.
* **"Decryption error":** Check key/ciphertext pairings; make sure files are not corrupted or mismatched.
* **PyCryptodome not found:** Run `pip install pycryptodome`.

---

## License

MIT License (see [LICENSE](LICENSE))

---

**CrypticComm is an open-source project for exploring, teaching, and demystifying public-key cryptography. Contributions and suggestions are welcome!**

---

*Built with ❤️ by [rsvptr](https://github.com/rsvptr) and the open-source cryptography community.*
