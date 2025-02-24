import streamlit as st
import requests
import json

# Add background image.
def add_bg_from_url():
    st.markdown(
        """
        <style>
        .stApp {
            background-image: url("https://images.unsplash.com/photo-1542736488-1967b42fcf54?q=80");
            background-attachment: fixed;
            background-size: cover;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

add_bg_from_url()

# SageMathCell API endpoint (do not include trailing slash)
SAGE_CELL_URL = "https://sagecell.sagemath.org/service"

def run_sage_code(code: str) -> str:
    """
    Sends URL-encoded SageMath code to the SageMathCell API and returns its output.
    """
    # URL-encode the code as required by the SageMathCell API.
    payload = "code=" + requests.utils.quote(code)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = requests.post(SAGE_CELL_URL, data=payload, headers=headers, timeout=60)
        if response.status_code != 200:
            return f"Error: Received status code {response.status_code}"
        result = response.json()
        stdout = result.get("stdout", "")
        return stdout if stdout.strip() else "No output received."
    except Exception as e:
        return f"Error calling SageMathCell API: {e}"

st.title("CrypticComm: RSA Communication Tool Dashboard")

# ─────────────────────────────────────────────────────────────
# Connectivity Test (Sidebar)
# ─────────────────────────────────────────────────────────────
st.sidebar.subheader("SageMathCell Connectivity Test")
if st.sidebar.button("Run Connectivity Test"):
    test_code = "print('SageMathCell Connectivity Test: OK')"
    test_output = run_sage_code(test_code)
    if "OK" in test_output:
        st.sidebar.success("Successfully connected to SageMathCell server!")
    else:
        st.sidebar.error("Failed to connect to SageMathCell server.")
    st.sidebar.text_area("Test Output", test_output, height=100)

# ─────────────────────────────────────────────────────────────
# Phase Selector
# ─────────────────────────────────────────────────────────────
phase = st.sidebar.selectbox("Select Phase", ["Key Generation", "Encryption", "Decryption"])

# ─────────────────────────────────────────────────────────────
# Phase 1: Key Generation
# ─────────────────────────────────────────────────────────────
if phase == "Key Generation":
    st.header("Phase 1: RSA Key Generation (Group A)")
    st.markdown(
        "Click the button below to generate RSA keys with 300-digit primes. The **public key** "
        "will be shared with Group B, and the **private key** will remain confidential."
    )
    if st.button("Generate RSA Keys"):
        sage_code = r"""
from sage.all import *
import time, json

# Set random seed based on current time
seed_primes = int(time.time())
set_random_seed(seed_primes)
min_limit = Integer(10**299)
max_limit = Integer(10**300 - 1)

def generate_prime():
    while True:
        candidate = random_prime(max_limit, lbound=min_limit)
        if candidate.ndigits() == 300:
            return candidate

# Generate prime p
p = generate_prime()

# Generate prime q such that |p - q| is large enough
difference_threshold = Integer(10**200)
max_trials = 1000
trial = 0
while trial < max_trials:
    q = generate_prime()
    if abs(p - q) >= difference_threshold:
        break
    trial += 1

# Compute modulus and totient
n = p * q
phi_n = (p - 1) * (q - 1)

# Select public exponent e
def select_public_exponent(phi):
    while True:
        e_candidate = randint(2**16, phi - 1)
        if gcd(e_candidate, phi) == 1:
            return e_candidate

e = select_public_exponent(phi_n)
d = inverse_mod(e, phi_n)

# Output the keys as JSON
print(json.dumps({
    "public": {
        "n": str(n),
        "e": str(e)
    },
    "private": {
        "d": str(d)
    }
}))
"""
        output = run_sage_code(sage_code)
        try:
            key_data = json.loads(output)
            public_key = key_data.get("public", {})
            private_key = key_data.get("private", {})
            formatted_output = (
                "### Public Key:\n\n"
                f"**n:** {public_key.get('n', '')}\n\n"
                f"**e:** {public_key.get('e', '')}\n\n"
                "### Private Key:\n\n"
                f"**d:** {private_key.get('d', '')}"
            )
        except Exception as ex:
            formatted_output = f"Error parsing key data:\n{output}"
        st.markdown(formatted_output)

# ─────────────────────────────────────────────────────────────
# Phase 2: Encryption
# ─────────────────────────────────────────────────────────────
elif phase == "Encryption":
    st.header("Phase 2: Message Encryption (Group B)")
    st.markdown(
        "Enter the **public key** parameters, n and e provided by Group A and type your message "
        "segments (one per line). Each segment will be encrypted using RSA."
    )
    n_val = st.text_input("Public Key (n)", placeholder="Enter modulus, n")
    e_val = st.text_input("Public Exponent (e)", placeholder="Enter exponent, e")
    segments_text = st.text_area("Message Segments", 
                                 placeholder="Enter one message segment per line")
    if st.button("Encrypt Message Segments"):
        if not n_val or not e_val:
            st.error("Please provide both n and e values.")
        else:
            segments = [seg for seg in segments_text.splitlines() if seg.strip() != ""]
            segments_json = json.dumps(segments)
            sage_code = f"""
from sage.all import *
import json

def text_to_number(text):
    bytes_rep = text.encode('utf-8')
    return Integer(int.from_bytes(bytes_rep, 'big'))

n = Integer({n_val})
e = Integer({e_val})
segments = {segments_json}
encrypted_segments = []

for text in segments:
    number = text_to_number(text)
    if number >= n:
        print("Error: A segment is too large for the modulus n.")
        exit()
    cipher = power_mod(number, e, n)
    encrypted_segments.append(str(cipher))

print(json.dumps({{"encrypted_segments": encrypted_segments}}))
"""
            output = run_sage_code(sage_code)
            try:
                data = json.loads(output)
                enc_list = data.get("encrypted_segments", [])
                formatted_output = "### Encrypted Segments:\n"
                for i, cipher in enumerate(enc_list, 1):
                    formatted_output += f"\n**Segment {i}:**\n{cipher}\n"
            except Exception as ex:
                formatted_output = f"Error parsing encrypted data:\n{output}"
            st.markdown(formatted_output)

# ─────────────────────────────────────────────────────────────
# Phase 3: Decryption
# ─────────────────────────────────────────────────────────────
elif phase == "Decryption":
    st.header("Phase 3: Message Decryption (Group A)")
    st.markdown(
        "Enter the **modulus, n** and your **private key**, d along with the encrypted message segments "
        "received from Group B. The tool will decrypt the segments and reconstruct the original message."
    )
    n_val = st.text_input("Modulus (n)", placeholder="Enter modulus, n", key="n_decrypt")
    d_val = st.text_input("Private Exponent (d)", placeholder="Enter private exponent, d", key="d_decrypt")
    encrypted_segments_text = st.text_area("Encrypted Segments", 
                                           placeholder="Enter one ciphertext per line")
    if st.button("Decrypt Message Segments"):
        if not n_val or not d_val:
            st.error("Please provide both n and d values.")
        else:
            segments = [seg for seg in encrypted_segments_text.splitlines() if seg.strip() != ""]
            segments_json = json.dumps(segments)
            sage_code = f"""
from sage.all import *
import json

def number_to_text(number):
    hex_str = '%x' % number
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    bytes_rep = bytes.fromhex(hex_str)
    return bytes_rep.decode('utf-8')

n = Integer({n_val})
d = Integer({d_val})
segments = {segments_json}
decrypted_segments = []

for cipher in segments:
    cipher_int = Integer(cipher)
    number = power_mod(cipher_int, d, n)
    try:
        text = number_to_text(number)
    except Exception as error:
        text = "Error decoding segment: " + str(error)
    decrypted_segments.append(text)

print(json.dumps({{"decrypted_segments": decrypted_segments}}))
"""
            output = run_sage_code(sage_code)
            try:
                data = json.loads(output)
                dec_list = data.get("decrypted_segments", [])
                formatted_output = "### Decrypted Message Segments:\n"
                for i, segment in enumerate(dec_list, 1):
                    formatted_output += f"\n**Segment {i}:**\n{segment}\n"
            except Exception as ex:
                formatted_output = f"Error parsing decrypted data:\n{output}"
            st.markdown(formatted_output)
