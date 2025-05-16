import streamlit as st
import base64
import json
import io
import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ----------- Utility Functions -----------

def nowstr():
    """Return the current timestamp as a compact string."""
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

def key_to_dict(key):
    """Convert RSA key into serializable dictionary format (public and private)."""
    pub = key.publickey()
    return {
        "public": {"n": str(pub.n), "e": str(pub.e)},
        "private": {
            "d": str(key.d),
            "n": str(key.n),
            "e": str(key.e),
            "p": str(key.p),
            "q": str(key.q)
        }
    }

def download_button_dict(data, label, fname):
    """Create a download button for a given dict, with a JSON filename."""
    json_bytes = json.dumps(data, indent=2).encode()
    return st.download_button(
        label=label,
        data=json_bytes,
        file_name=fname,
        mime="application/json"
    )

def upload_json_dict(label, key=None):
    """
    Streamlit file uploader for JSON files.
    Returns parsed data or None if nothing uploaded/invalid.
    """
    uploaded = st.file_uploader(label, type=["json"], key=key)
    if uploaded:
        try:
            data = json.load(uploaded)
            return data
        except Exception as e:
            st.error(f"Could not load file: {e}")
    return None

def text_to_int(text):
    """Encode string as big integer."""
    return int.from_bytes(text.encode("utf-8"), byteorder="big")

def int_to_text(i):
    """Decode integer to UTF-8 string (handles padding automatically)."""
    try:
        return i.to_bytes((i.bit_length() + 7) // 8, byteorder="big").decode("utf-8")
    except Exception as e:
        return f"[Decode error: {e}]"

def segment_message_utf8(msg, max_bytes):
    """
    Split a message into segments, each <= max_bytes, not breaking UTF-8 chars.
    Ensures safe RSA encryption for each segment.
    """
    msg_bytes = msg.encode("utf-8")
    segments = []
    idx = 0
    while idx < len(msg_bytes):
        seg_bytes = msg_bytes[idx:idx+max_bytes]
        # Don't split a multi-byte UTF-8 character at segment end
        while True:
            try:
                seg_bytes.decode("utf-8")
                break
            except UnicodeDecodeError:
                seg_bytes = seg_bytes[:-1]
        segments.append(seg_bytes.decode("utf-8"))
        idx += len(seg_bytes)
    return segments

def encrypt_segment(segment, n, e, use_oaep=False):
    """
    Encrypt one message segment using either textbook RSA or OAEP.
    OAEP is safer for real use.
    """
    if use_oaep:
        pubkey = RSA.construct((n, e))
        cipher = PKCS1_OAEP.new(pubkey)
        msg_bytes = segment.encode("utf-8")
        enc = cipher.encrypt(msg_bytes)
        # Base64 encode so the result can be stored as a string
        return base64.b64encode(enc).decode()
    else:
        m = text_to_int(segment)
        if m >= n:
            raise ValueError("Segment too large for modulus (try shorter message or use a larger key)")
        c = pow(m, e, n)
        return str(c)

def decrypt_segment(segment, n, d, use_oaep=False):
    """
    Decrypt one segment using textbook RSA or OAEP, as appropriate.
    Returns string or error string.
    """
    if use_oaep:
        try:
            privkey = RSA.construct((n, 65537, d))
            cipher = PKCS1_OAEP.new(privkey)
            pt_bytes = cipher.decrypt(base64.b64decode(segment))
            return pt_bytes.decode("utf-8")
        except Exception as e:
            return f"[Decryption error: {e}]"
    else:
        try:
            c = int(segment)
            m = pow(c, d, n)
            return int_to_text(m)
        except Exception as e:
            return f"[Decryption error: {e}]"

def clipboard_copy(text, label):
    """
    Show a code box with a 'Copy' button (manual copy, since Streamlit can't access clipboard directly).
    """
    st.code(text, language="json")
    st.button("📋 Copy to clipboard (select and copy)", key=label, help="Copy this manually")

# ----------- Streamlit App Layout/Logic -----------

# Configure page and style background
st.set_page_config(page_title="CrypticComm", layout="centered")
st.markdown("""
    <style>
    .stApp { 
        background-image: url("https://images.unsplash.com/photo-1636956026491-86a9da7001c9?q=80");
        background-size: cover;
    }
    </style>
    """, unsafe_allow_html=True)

st.title("🔐 CrypticComm: RSA Communication Tool")

# Sidebar phase selection
st.sidebar.title("Navigation")
phase = st.sidebar.radio("Choose Phase", ["Key Generation", "Encryption", "Decryption"])

# ---------------- PHASE 1: KEY GENERATION ----------------

if phase == "Key Generation":
    st.header("Phase 1: Key Generation (Group A)")
    st.markdown("""
    - **Public Key**: Share with Group B.
    - **Private Key**: Keep secret.
    - You can always redownload your keys after generation.
    """)

    # User chooses key size (default 2048)
    keysize = st.number_input(
        "Key Size (bits)", min_value=1024, max_value=8192, value=2048, step=256,
        help="2048 bits is secure for educational use; 4096 for extra caution (slower)."
    )

    # Store generated key in session so user can re-download it
    if "generated_key" not in st.session_state:
        st.session_state.generated_key = None
        st.session_state.generated_time = None

    # Generate new key when button pressed
    if st.button("🔑 Generate New RSA Keys"):
        with st.spinner("Generating keys..."):
            key = RSA.generate(keysize)
            st.session_state.generated_key = key_to_dict(key)
            st.session_state.generated_time = nowstr()
        st.success("RSA key pair generated!")

    # If a key has been generated, show download, display options
    if st.session_state.generated_key:
        public_key = st.session_state.generated_key["public"]
        private_key = st.session_state.generated_key["private"]
        gen_time = st.session_state.generated_time

        st.subheader("Public Key")
        clipboard_copy(json.dumps(public_key, indent=2), label="pubkey_copy")
        download_button_dict(public_key, f"⬇️ Download Public Key ({gen_time})", f"rsa_pub_{gen_time}.json")
        st.info("Share this public key with your communication partner.")

        st.subheader("Private Key")
        show_priv = st.checkbox("Show private key", value=False)
        if show_priv:
            st.code(json.dumps(private_key, indent=2), language="json")
        download_button_dict(private_key, f"⬇️ Download Private Key ({gen_time})", f"rsa_priv_{gen_time}.json")
        st.warning("NEVER share your private key. Store it securely.")

        # For technical details
        with st.expander("Key Details"):
            st.json(st.session_state.generated_key)

# ---------------- PHASE 2: ENCRYPTION ----------------

elif phase == "Encryption":
    st.header("Phase 2: Encryption (Group B)")
    st.markdown("""
    1. Load or paste the **public key** (from Group A).
    2. Write your message to encrypt. 
    3. Choose security options and encrypt.
    4. Download/share the resulting encrypted message.
    """)

    # Step 1: Load public key
    st.subheader("1. Public Key")
    pub_data = upload_json_dict("Upload Public Key (.json)", key="enc_pub_upload")
    if not pub_data:
        pub_raw = st.text_area(
            "Or paste Public Key JSON",
            placeholder='{"n": "<RSA modulus>", "e": "65537"}',
            key="enc_pub_paste"
        )
        pub_data = None
        # Only parse if user really entered JSON (not empty, not placeholder)
        if pub_raw.strip() and not pub_raw.strip().startswith("{") and not pub_raw.strip().startswith("["):
            st.info("Paste the public key JSON here if not uploading.")
        else:
            try:
                if pub_raw.strip() and pub_raw.strip() not in ["", "...", '"..."']:
                    pub_data = json.loads(pub_raw)
            except Exception:
                pass

    n, e = None, None
    pubkey = None
    keysize_bits = None
    if pub_data:
        try:
            # Parse modulus and exponent
            n = int(pub_data["n"])
            e = int(pub_data["e"])
            keysize_bits = n.bit_length()
            pubkey = RSA.construct((n, e))
            st.success(f"Public key loaded. Key size: {keysize_bits} bits.")
        except Exception as ex:
            n, e, pubkey = None, None, None
            st.warning("Waiting for valid public key input...")

    # Step 2: Enter message
    st.subheader("2. Your Message")
    message = st.text_area(
        "Enter your message (UTF-8 supported)", "",
        help="Messages are split into segments that fit into the key size."
    )

    # Step 3: Select padding scheme (OAEP is safest)
    st.subheader("3. Encryption Options")
    use_oaep = st.checkbox(
        "Use OAEP Padding (highly recommended)", value=True,
        help="OAEP prevents deterministic attacks. Only turn off for textbook RSA demonstration."
    )

    # Compute segment size and show info
    max_seg_bytes = 0
    if pubkey:
        try:
            if use_oaep:
                max_seg_bytes = pubkey.size_in_bytes() - 2*20 - 2
            else:
                max_seg_bytes = (n.bit_length() - 1) // 8
            st.info(f"Maximum UTF-8 bytes per segment: {max_seg_bytes}")
        except Exception:
            pass

    # Step 4: Encrypt on button press (after key+message entered)
    encrypt_clicked = st.button("🔒 Encrypt Message")
    if encrypt_clicked:
        if not (pubkey and message.strip()):
            st.error("Please provide a valid public key and a non-empty message before encrypting.")
        else:
            try:
                # Split message and encrypt each segment
                segments = segment_message_utf8(message, max_seg_bytes)
                st.success(f"Your message is split into {len(segments)} segment(s).")
                encrypted = []
                for i, seg in enumerate(segments, 1):
                    try:
                        ct = encrypt_segment(seg, n, e, use_oaep=use_oaep)
                        encrypted.append(ct)
                        st.info(f"Segment {i}: encrypted.")
                    except Exception as err:
                        st.error(f"Segment {i} error: {err}")
                        encrypted.append(f"[Error: {err}]")
                # Build JSON output and provide download
                output = {
                    "segments": encrypted,
                    "oaep": use_oaep,
                    "num_segments": len(segments),
                    "key_bits": n.bit_length()
                }
                enc_time = nowstr()
                st.subheader("Encrypted Segments")
                st.code(json.dumps(output, indent=2), language="json")
                download_button_dict(output, f"⬇️ Download Encrypted Message ({enc_time})", f"rsa_encrypted_{enc_time}.json")
            except Exception as ex:
                st.error(f"Encryption failed: {ex}")

# ---------------- PHASE 3: DECRYPTION ----------------

elif phase == "Decryption":
    st.header("Phase 3: Decryption (Group A)")
    st.markdown("""
    1. Load or paste your **private key**.
    2. Load or paste the **encrypted message**.
    3. Decrypt to reconstruct the original message.
    """)

    # Step 1: Load private key
    st.subheader("1. Private Key")
    priv_data = upload_json_dict("Upload Private Key (.json)", key="dec_priv_upload")
    if not priv_data:
        priv_raw = st.text_area(
            "Or paste Private Key JSON",
            placeholder='{"n": "<RSA modulus>", "d": "<private exponent>", "e": "65537"}',
            key="dec_priv_paste"
        )
        priv_data = None
        # Only parse if user entered JSON, not blank/placeholder
        if priv_raw.strip() and not priv_raw.strip().startswith("{") and not priv_raw.strip().startswith("["):
            st.info("Paste your private key JSON here if not uploading.")
        else:
            try:
                if priv_raw.strip() and priv_raw.strip() not in ["", "...", '"..."']:
                    priv_data = json.loads(priv_raw)
            except Exception:
                pass

    n, d, e = None, None, None
    privkey = None
    if priv_data:
        try:
            n = int(priv_data["n"])
            d = int(priv_data["d"])
            e = int(priv_data.get("e", 65537))
            privkey = RSA.construct((n, e, d))
            st.success(f"Private key loaded. Key size: {n.bit_length()} bits.")
        except Exception as ex:
            n, d, privkey = None, None, None
            st.warning("Waiting for valid private key input...")

    # Step 2: Load encrypted message
    st.subheader("2. Encrypted Message")
    enc_data = upload_json_dict("Upload Encrypted Message (.json)", key="dec_enc_upload")
    segments, use_oaep = [], False
    if not enc_data:
        enc_raw = st.text_area(
            "Or paste Encrypted Message JSON",
            placeholder='{"segments": ["base64_or_integer_ciphertexts_here"], "oaep": true, "num_segments": 2}',
            key="dec_enc_paste"
        )
        if enc_raw.strip() and not enc_raw.strip().startswith("{") and not enc_raw.strip().startswith("["):
            st.info("Paste the encrypted message JSON here if not uploading.")
        else:
            try:
                if enc_raw.strip() and enc_raw.strip() not in ["", "...", '"..."']:
                    enc_data = json.loads(enc_raw)
            except Exception:
                enc_data = None

    if enc_data:
        segments = enc_data.get("segments", [])
        use_oaep = enc_data.get("oaep", False)
        st.info(f"{len(segments)} encrypted segment(s) loaded. OAEP: {'yes' if use_oaep else 'no'}.")

    # Step 3: Decrypt when button pressed and data valid
    decrypt_clicked = st.button("🔓 Decrypt Message")
    if decrypt_clicked:
        if not (privkey and segments):
            st.error("Please provide a valid private key and encrypted message before decrypting.")
        else:
            decrypted, errors = [], 0
            for i, ct in enumerate(segments, 1):
                pt = decrypt_segment(ct, n, d, use_oaep=use_oaep)
                if pt.startswith("[Decryption error"):
                    errors += 1
                    st.error(f"Segment {i} error: {pt}")
                else:
                    st.success(f"Segment {i} OK.")
                decrypted.append(pt)
            st.subheader("Decrypted Message")
            final = "".join([pt for pt in decrypted if not pt.startswith("[Decryption error")])
            st.code(final, language="text")
            if errors:
                st.warning(f"{errors} segment(s) failed to decrypt.")

# ---- Footer ----
st.markdown("""
<hr>
<small>
CrypticComm - End-to-end RSA in Python for secure group messaging exercises.<br>
All processing is done in-browser. <b>Do not use for real secrets.</b>
</small>
""", unsafe_allow_html=True)
