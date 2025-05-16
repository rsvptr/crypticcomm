import streamlit as st
import base64
import json
from Crypto.Util import number
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import io

# ---- Streamlit Page Config ----
st.set_page_config(page_title="CrypticComm", layout="centered")
st.markdown("""
    <style>
    .stApp { 
        background-image: url("https://images.unsplash.com/photo-1636956026491-86a9da7001c9?q=80");
        background-size: cover;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🔐 CrypticComm: RSA Communication Tool Dashboard")

# ---- Sidebar: Phase Selector ----
phase = st.sidebar.radio("Select Phase", ["Key Generation", "Encryption", "Decryption"])
st.sidebar.info("All operations are performed locally in your browser for privacy.")

# ---- Helper Functions ----

def generate_rsa_keypair(bits=2048):
    """Generate an RSA keypair using PyCryptodome."""
    key = RSA.generate(bits)
    return key

def get_key_as_dict(key):
    """Extract public/private components as dicts for serialization."""
    pub = key.publickey()
    return {
        "public": {"n": str(pub.n), "e": str(pub.e)},
        "private": {"d": str(key.d), "n": str(key.n), "e": str(key.e), "p": str(key.p), "q": str(key.q)}
    }

def save_keyfile(data, filename):
    b = io.BytesIO()
    b.write(json.dumps(data, indent=2).encode())
    b.seek(0)
    st.download_button(f"⬇️ Download {filename}", b, file_name=filename, mime="application/json")

def load_keyfile(uploaded_file):
    try:
        content = uploaded_file.read()
        return json.loads(content)
    except Exception as e:
        st.error(f"Error loading key file: {e}")
        return None

def text_to_int(text):
    """Convert UTF-8 string to int."""
    return int.from_bytes(text.encode("utf-8"), byteorder="big")

def int_to_text(i):
    """Convert int back to UTF-8 string."""
    try:
        return i.to_bytes((i.bit_length() + 7) // 8, byteorder="big").decode("utf-8")
    except Exception as e:
        return f"[Decoding error: {e}]"

def segment_message(msg, n, safe_mode=True):
    """Split the message so each segment can fit into n-1 bits."""
    # Safe mode: segment at bytes level to avoid breaking UTF-8 multibyte chars
    max_bytes = (n.bit_length() - 1) // 8
    msg_bytes = msg.encode("utf-8")
    segments = []
    idx = 0
    while idx < len(msg_bytes):
        seg_bytes = msg_bytes[idx:idx+max_bytes]
        # Ensure we don't split a multibyte character
        while True:
            try:
                seg_bytes.decode("utf-8")
                break
            except UnicodeDecodeError:
                seg_bytes = seg_bytes[:-1]
        segments.append(seg_bytes.decode("utf-8"))
        idx += len(seg_bytes)
    return segments

def encrypt_segment(plain_text, n, e, use_oaep=False):
    if use_oaep:
        pubkey = RSA.construct((n, e))
        cipher = PKCS1_OAEP.new(pubkey)
        # OAEP limits message size: k - 2*hLen - 2
        max_bytes = (pubkey.size_in_bytes()) - 2*20 - 2
        msg_bytes = plain_text.encode("utf-8")
        if len(msg_bytes) > max_bytes:
            raise ValueError("Message segment too large for modulus (OAEP).")
        encrypted = cipher.encrypt(msg_bytes)
        return base64.b64encode(encrypted).decode()
    else:
        m = text_to_int(plain_text)
        if m >= n:
            raise ValueError("Message segment is too large for modulus n.")
        c = pow(m, e, n)
        return str(c)

def decrypt_segment(ciphertext, n, d, use_oaep=False):
    if use_oaep:
        privkey = RSA.construct((n, 65537, d))
        cipher = PKCS1_OAEP.new(privkey)
        try:
            ct = base64.b64decode(ciphertext)
            pt_bytes = cipher.decrypt(ct)
            return pt_bytes.decode("utf-8")
        except Exception as e:
            return f"[Decryption error: {e}]"
    else:
        try:
            c = int(ciphertext)
            m = pow(c, d, n)
            return int_to_text(m)
        except Exception as e:
            return f"[Decryption error: {e}]"

# ---- Phase 1: Key Generation ----
if phase == "Key Generation":
    st.header("Phase 1: RSA Key Generation (Group A)")

    st.markdown("""
        Generate RSA key pairs for secure communication.
        - **Public Key (n, e)**: Share this with Group B.
        - **Private Key (d, n, e, p, q)**: Keep this secure, use for decryption.
        """)
    bits = st.number_input("Key Size (bits)", min_value=1024, max_value=8192, value=2048, step=256)
    if st.button("🔑 Generate RSA Keys"):
        with st.spinner("Generating secure primes..."):
            key = generate_rsa_keypair(bits)
            key_dict = get_key_as_dict(key)
        st.success("RSA Key Pair Generated!")

        st.subheader("Public Key")
        st.code(json.dumps(key_dict["public"], indent=2), language="json")
        save_keyfile(key_dict["public"], "rsa_public_key.json")
        st.write("")

        st.subheader("Private Key")
        st.code(json.dumps(key_dict["private"], indent=2), language="json")
        save_keyfile(key_dict["private"], "rsa_private_key.json")
        st.warning("Keep your private key file secure!")

        # Option to show all parameters if wanted
        with st.expander("Show key details"):
            st.json(key_dict)

# ---- Phase 2: Encryption ----
elif phase == "Encryption":
    st.header("Phase 2: Message Encryption (Group B)")

    st.markdown("""
        1. Load or paste the **public key** `(n, e)` from Group A.
        2. Write your message (recommended: short segments for clarity).
        3. Choose encryption padding.
        4. Encrypt!  
        Encrypted message segments can be sent to Group A for decryption.
        """)
    st.subheader("1. Provide Public Key")
    pub_key_file = st.file_uploader("Upload Public Key JSON", type=["json"])
    if pub_key_file:
        pub_key = load_keyfile(pub_key_file)
        n = int(pub_key["n"])
        e = int(pub_key["e"])
    else:
        n = st.text_input("Public Key Modulus (n)")
        e = st.text_input("Public Key Exponent (e)")
        try:
            n = int(n)
            e = int(e)
        except Exception:
            n = None
            e = None

    st.subheader("2. Enter Your Message")
    message = st.text_area("Message to encrypt", placeholder="Enter your message here...")

    st.subheader("3. Encryption Settings")
    use_oaep = st.checkbox("Use OAEP Padding (recommended for security)", value=True)

    if st.button("🔒 Encrypt Message") and n and e and message:
        try:
            # Split message into valid-length segments
            if use_oaep:
                # OAEP limits: 190 bytes for 2048 bits, 446 for 4096, etc.
                pubkey = RSA.construct((n, e))
                max_bytes = pubkey.size_in_bytes() - 2*20 - 2
            else:
                max_bytes = (n.bit_length() - 1) // 8
            segments = segment_message(message, n, safe_mode=True)
            st.info(f"Message split into {len(segments)} segments (max bytes per segment: {max_bytes}).")
            encrypted = []
            for i, seg in enumerate(segments, 1):
                ct = encrypt_segment(seg, n, e, use_oaep=use_oaep)
                encrypted.append(ct)
                st.success(f"Segment {i}: encrypted.")

            enc_json = json.dumps({
                "segments": encrypted,
                "oaep": use_oaep,
                "num_segments": len(segments)
            }, indent=2)

            st.markdown("### Encrypted Message Segments")
            st.code(enc_json, language="json")
            save_keyfile(json.loads(enc_json), "encrypted_message.json")

        except Exception as ex:
            st.error(f"Encryption failed: {ex}")

# ---- Phase 3: Decryption ----
elif phase == "Decryption":
    st.header("Phase 3: Message Decryption (Group A)")
    st.markdown("""
        1. Load your **private key** and receive the encrypted message JSON from Group B.
        2. The tool will decrypt each segment and reconstruct the original message.
        """)

    st.subheader("1. Load Private Key")
    priv_key_file = st.file_uploader("Upload Private Key JSON", type=["json"])
    if priv_key_file:
        priv_key = load_keyfile(priv_key_file)
        n = int(priv_key["n"])
        d = int(priv_key["d"])
        e = int(priv_key["e"])
    else:
        n = st.text_input("Private Key Modulus (n)")
        d = st.text_input("Private Exponent (d)")
        e = st.text_input("Public Exponent (e)", value="65537")
        try:
            n = int(n)
            d = int(d)
            e = int(e)
        except Exception:
            n = None
            d = None
            e = None

    st.subheader("2. Load Encrypted Segments")
    enc_file = st.file_uploader("Upload Encrypted Segments JSON", type=["json"])
    if enc_file:
        enc_data = load_keyfile(enc_file)
        segments = enc_data["segments"]
        use_oaep = enc_data.get("oaep", False)
    else:
        enc_segments_text = st.text_area("Paste Encrypted Segments (JSON array)", placeholder='["..."]')
        try:
            enc_data = json.loads(enc_segments_text)
            segments = enc_data["segments"] if isinstance(enc_data, dict) else enc_data
            use_oaep = enc_data.get("oaep", False) if isinstance(enc_data, dict) else False
        except Exception:
            segments = []
            use_oaep = False

    if st.button("🔓 Decrypt Segments") and n and d and segments:
        decrypted = []
        errors = 0
        for i, ct in enumerate(segments, 1):
            pt = decrypt_segment(ct, n, d, use_oaep=use_oaep)
            if pt.startswith("[Decryption error"):
                errors += 1
                st.error(f"Segment {i}: {pt}")
            else:
                st.success(f"Segment {i}: {pt}")
            decrypted.append(pt)
        st.markdown("### Decrypted Message (Concatenated):")
        st.code("".join([pt for pt in decrypted if not pt.startswith("[Decryption error")]), language="text")
        if errors:
            st.warning(f"{errors} segment(s) could not be decoded.")

# ---- Footer ----
st.markdown("""
<hr>
<small>
    CrypticComm: All cryptography performed in-browser with PyCryptodome. 
    <br>
    <b>Warning:</b> For educational use only; do not use for production secrets!
</small>
""", unsafe_allow_html=True)
