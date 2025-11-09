import streamlit as st
import re
import random
from typing import Optional, Tuple, List

# Page configuration
st.set_page_config(
    page_title="Heartbleed Vulnerability Demo",
    page_icon="🔒",
    layout="wide"
)

# ============================================================================
# DUMMY SENSITIVE DATA - For Educational Demonstration Only
# All data is fake and does not represent real credentials or sensitive information
# ============================================================================

DUMMY_SENSITIVE_DATA = {
    "private_key": """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1+f4Sw7+7QxKh6BQm6tLF2N8q4k3Q2Y3Q4Z5W6X7Y8Z9A0
B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0F1G2
H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1A2B3C4D5E6F7G8H9I0J1K2L3M4
N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6
T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8
-----END PRIVATE KEY-----
NOTE: This is a DUMMY key for educational purposes only""",
    
    "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZHVtbXlfdXNlciIsInBhc3N3b3JkIjoiZHVtbXlfMTIzNDU2Iiwicm9sZSI6InVzZXIiLCJleHAiOjE3MDAwMDAwMDB9.abcdefghijklmnopqrstuvwxyz1234567890DUMMY_TOKEN",
    
    "credit_card": "0000-0000-0000-0000",
    "cvv": "000",
    "expiry": "00/00",
    
    "password": "dummy_password_12345",
    "username": "dummy_user",
    
    "api_key": "sk_test_000000000000000000000000000000000000000000000000",
    "secret_key": "sec_test_000000000000000000000000000000000000000000000000",
    
    "database_url": "postgresql://dummy_user:dummy_pass@localhost:5432/dummy_db",
    "redis_password": "dummy_redis_password_12345",
    
    "email": "dummy@example.com",
    "phone": "+1-555-000-0000",
    
    "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDummyKeyForDemoOnly...",
    
    "oauth_token": "dummy_oauth_token_1234567890abcdef",
}

# ============================================================================
# BACKEND LOGIC (Integrated into Streamlit app)
# ============================================================================

def generate_memory_dump() -> bytes:
    """
    Simulate memory dump that could contain sensitive data.
    In a real Heartbleed attack, this would be actual memory from the server.
    All data is dummy/fake for educational purposes.
    """
    # Create a buffer with some dummy sensitive data scattered around
    memory = bytearray(65536)  # 64KB buffer
    
    # Fill with random data
    for i in range(len(memory)):
        memory[i] = random.randint(0, 255)
    
    # Inject dummy sensitive data at various offsets with labels
    # Add newlines to separate data from random bytes for better extraction
    dummy_strings = [
        # Labels first
        b"=== PRIVATE KEY START ===\n",
        bytes(DUMMY_SENSITIVE_DATA["private_key"], "utf-8") + b"\n",
        b"=== PRIVATE KEY END ===\n",
        
        b"SESSION_TOKEN: " + bytes(DUMMY_SENSITIVE_DATA["session_token"], "utf-8") + b"\n",
        b"PASSWORD: " + bytes(DUMMY_SENSITIVE_DATA["password"], "utf-8") + b"\n",
        b"USERNAME: " + bytes(DUMMY_SENSITIVE_DATA["username"], "utf-8") + b"\n",
        
        b"API_KEY: " + bytes(DUMMY_SENSITIVE_DATA["api_key"], "utf-8") + b"\n",
        b"SECRET_KEY: " + bytes(DUMMY_SENSITIVE_DATA["secret_key"], "utf-8") + b"\n",
        
        b"CREDIT_CARD: " + bytes(DUMMY_SENSITIVE_DATA["credit_card"], "utf-8") + b"\n",
        b"CVV: " + bytes(DUMMY_SENSITIVE_DATA["cvv"], "utf-8") + b"\n",
        b"EXPIRY: " + bytes(DUMMY_SENSITIVE_DATA["expiry"], "utf-8") + b"\n",
        
        b"DATABASE_URL: " + bytes(DUMMY_SENSITIVE_DATA["database_url"], "utf-8") + b"\n",
        b"REDIS_PASSWORD: " + bytes(DUMMY_SENSITIVE_DATA["redis_password"], "utf-8") + b"\n",
        
        b"EMAIL: " + bytes(DUMMY_SENSITIVE_DATA["email"], "utf-8") + b"\n",
        b"PHONE: " + bytes(DUMMY_SENSITIVE_DATA["phone"], "utf-8") + b"\n",
        
        b"SSH_KEY: " + bytes(DUMMY_SENSITIVE_DATA["ssh_key"], "utf-8") + b"\n",
        b"OAUTH_TOKEN: " + bytes(DUMMY_SENSITIVE_DATA["oauth_token"], "utf-8") + b"\n",
    ]
    
    # Distribute dummy data throughout memory at various offsets
    # Use offsets that give enough space for each data item
    offsets = [100, 800, 1500, 3000, 6000, 12000, 18000, 25000, 35000, 45000, 55000, 60000, 62000, 63000, 64000, 65000]
    offset_idx = 0
    for data in dummy_strings:
        if offset_idx < len(offsets):
            start = offsets[offset_idx]
            end = min(start + len(data), len(memory))
            # Only write if we have enough space
            if end - start >= len(data):
                memory[start:start + len(data)] = data
            else:
                # Write what we can
                memory[start:end] = data[:end-start]
            offset_idx += 1
    
    return bytes(memory)

def process_heartbeat(payload: str, payload_length: int) -> dict:
    """
    VULNERABLE HEARTBEAT FUNCTION - This mimics the Heartbleed vulnerability.
    
    The vulnerability: The server trusts the payload_length field from the client
    without properly validating it against the actual payload size.
    
    In the real Heartbleed bug, OpenSSL would:
    1. Allocate a buffer based on payload_length (up to 64KB)
    2. Copy the payload (which might be smaller)
    3. Return the buffer, which includes uninitialized memory (the leak)
    """
    actual_payload_size = len(payload.encode('utf-8'))
    
    # VULNERABILITY: Server trusts client-provided payload_length
    # without validating it matches the actual payload size
    declared_length = payload_length
    
    # Simulate the vulnerable behavior
    # Allocate buffer based on declared length (up to 64KB)
    max_length = min(declared_length, 65536)  # Max 64KB like in Heartbleed
    
    # Create response buffer
    response_buffer = bytearray(max_length)
    
    # Copy the actual payload (which might be smaller)
    payload_bytes = payload.encode('utf-8')
    payload_size = len(payload_bytes)
    
    # Copy payload to buffer
    response_buffer[:payload_size] = payload_bytes
    
    # VULNERABILITY: The rest of the buffer contains uninitialized memory
    # In real Heartbleed, this would be actual memory from the server process
    if max_length > payload_size:
        # Simulate memory leak - append memory dump
        memory_dump = generate_memory_dump()
        leak_size = max_length - payload_size
        response_buffer[payload_size:max_length] = memory_dump[:leak_size]
    
    # Convert to string (this simulates sending the buffer back)
    # In real attack, this would leak actual server memory
    response_data = response_buffer[:max_length].decode('utf-8', errors='ignore')
    
    leaked_bytes = max_length - payload_size
    
    return {
        "response": response_data,
        "actual_length": actual_payload_size,
        "leaked_bytes": leaked_bytes
    }

# ============================================================================
# FRONTEND HELPER FUNCTIONS
# ============================================================================

def clean_text(text: str) -> str:
    """Remove non-printable characters and replace with dots"""
    # Only keep printable ASCII characters (32-126) and common whitespace
    return ''.join(c if (32 <= ord(c) <= 126) or c in '\n\r\t' else '.' for c in text)

def extract_readable_strings(data: str, min_length: int = 4) -> List[Tuple[str, int]]:
    """Extract readable ASCII strings from leaked data"""
    # Clean the data first to handle encoding issues
    cleaned = clean_text(data)
    # Find sequences of printable ASCII characters (no dots)
    pattern = r'[!-~]{' + str(min_length) + ',}'
    matches = []
    for match in re.finditer(pattern, cleaned):
        string = match.group()
        # Filter out garbage patterns
        # 1. Must have at least 3 different characters
        if len(set(string)) < 3:
            continue
        # 2. Filter out strings that are mostly repeated characters (like "AAAAAAA")
        if len(string) > 10:
            char_counts = {}
            for char in string:
                char_counts[char] = char_counts.get(char, 0) + 1
            max_repeats = max(char_counts.values())
            if max_repeats > len(string) * 0.7:  # More than 70% same character
                continue
        # 3. Filter out obvious garbage patterns (but be careful not to filter valid data)
        # Only filter if it's ALL special characters with no alphanumeric content
        if not re.search(r'[a-zA-Z0-9]', string):
            continue
        matches.append((string, match.start()))
    return matches

def format_to_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Convert binary data to a hex dump format"""
    hex_dump = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        # Hex representation
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        # ASCII representation (printable only)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        # Pad hex part to align ASCII
        hex_part = hex_part.ljust(bytes_per_line * 3)
        hex_dump.append(f"{i:08x}  {hex_part}  |{ascii_part}|")
    return '\n'.join(hex_dump)

def extract_structured_data(cleaned_data: str) -> dict:
    """Extract structured sensitive data from leaked memory"""
    extracted = {
        "private_keys": [],
        "credentials": [],
        "api_keys": [],
        "tokens": [],
        "payment_info": [],
        "database_info": [],
        "contact_info": [],
        "other": []
    }
    
    # Extract private keys (between BEGIN and END markers)
    # First try to find complete keys
    private_key_pattern = r'BEGIN\s+PRIVATE\s+KEY.*?END\s+PRIVATE\s+KEY'
    for match in re.finditer(private_key_pattern, cleaned_data, re.DOTALL | re.IGNORECASE):
        key_content = match.group(0)
        # Clean up the key content - remove excessive dots but keep structure
        key_content = re.sub(r'\.{5,}', ' ', key_content)  # Replace long dot sequences with space
        key_content = re.sub(r'\s+', '\n', key_content)  # Normalize whitespace
        # Filter out lines that are mostly garbage
        lines = [line for line in key_content.split('\n') if len(line.strip()) > 10 or 'BEGIN' in line or 'END' in line]
        key_content = '\n'.join(lines)
        if len(key_content) > 50:  # Valid key should be substantial
            extracted["private_keys"].append({
                "content": key_content.strip(),
                "offset": match.start(),
                "length": len(key_content)
            })
    
    # Also look for just the BEGIN marker with following content (in case END is cut off)
    begin_pattern = r'BEGIN\s+PRIVATE\s+KEY[^\n]*\n([A-Za-z0-9+/=\s]{50,})'
    for match in re.finditer(begin_pattern, cleaned_data, re.IGNORECASE):
        # Check if we already have this key
        key_start = match.start()
        if not any(abs(k['offset'] - key_start) < 100 for k in extracted["private_keys"]):
            key_content = match.group(0)
            key_content = re.sub(r'\.{5,}', ' ', key_content)
            key_content = re.sub(r'\s+', '\n', key_content)
            if len(key_content) > 50:
                extracted["private_keys"].append({
                    "content": key_content.strip() + "\n... (truncated)",
                    "offset": match.start(),
                    "length": len(key_content)
                })
    
    # Extract key-value pairs (LABEL: value format)
    kv_pattern = r'([A-Z_]+):\s*([^\n\r]{1,200})'
    for match in re.finditer(kv_pattern, cleaned_data):
        key = match.group(1).strip()
        value = match.group(2).strip().rstrip('.')
        
        # Skip if value is mostly dots (more than 50% dots)
        if len(value) > 0 and value.count('.') > len(value) * 0.5:
            continue
        
        # Skip if value has too many consecutive dots (likely corrupted)
        if '..' in value and value.count('..') > 2:
            continue
        
        # For EMAIL and PHONE, extract the actual value more carefully
        if key == "EMAIL":
            # Try to extract a clean email from the value
            # Remove any trailing garbage after a valid email
            email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', value)
            if email_match:
                clean_email = email_match.group(1)
                # Validate the email is reasonable
                if (clean_email.count('.') <= 3 and 
                    '..' not in clean_email and 
                    5 <= len(clean_email) <= 50):
                    extracted["contact_info"].append({
                        "type": "email",
                        "value": clean_email,
                        "offset": match.start()
                    })
            continue
        
        if key == "PHONE":
            # Extract phone number more carefully
            phone_match = re.search(r'(\+?[\d\-\(\)\s]{7,20})', value)
            if phone_match:
                clean_phone = phone_match.group(1).strip()
                if len(clean_phone) >= 7 and len(clean_phone) <= 20:
                    extracted["contact_info"].append({
                        "type": "phone",
                        "value": clean_phone,
                        "offset": match.start()
                    })
            continue
        
        # Categorize the extracted data
        if key in ["PASSWORD", "USERNAME"]:
            extracted["credentials"].append({
                "type": key.lower(),
                "value": value,
                "offset": match.start()
            })
        elif key in ["API_KEY", "SECRET_KEY"]:
            extracted["api_keys"].append({
                "type": key.lower(),
                "value": value,
                "offset": match.start()
            })
        elif key in ["SESSION_TOKEN", "OAUTH_TOKEN"]:
            extracted["tokens"].append({
                "type": key.lower(),
                "value": value,
                "offset": match.start()
            })
        elif key in ["CREDIT_CARD", "CVV", "EXPIRY"]:
            extracted["payment_info"].append({
                "type": key.lower(),
                "value": value,
                "offset": match.start()
            })
        elif key in ["DATABASE_URL", "REDIS_PASSWORD"]:
            extracted["database_info"].append({
                "type": key.lower(),
                "value": value,
                "offset": match.start()
            })
        elif key in ["SSH_KEY"]:
            extracted["other"].append({
                "type": key.lower(),
                "value": value[:100] + "..." if len(value) > 100 else value,
                "offset": match.start()
            })
    
    # Extract JWT tokens
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    for match in re.finditer(jwt_pattern, cleaned_data):
        token = match.group(0)
        # Check if we already have this token
        if not any(t['value'] == token for t in extracted["tokens"]):
            extracted["tokens"].append({
                "type": "jwt_token",
                "value": token,
                "offset": match.start()
            })
    
    # Extract email addresses (with validation to filter out corrupted random bytes)
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    for match in re.finditer(email_pattern, cleaned_data):
        email = match.group(0)
        
        # Skip if we already have this email
        if any(c['value'] == email for c in extracted["contact_info"] if c['type'] == 'email'):
            continue
        
        # Validate email: filter out corrupted emails
        # 1. Should not have excessive dots (more than 3 dots total is suspicious)
        if email.count('.') > 3:
            continue
        
        # 2. Should not have consecutive dots
        if '..' in email:
            continue
        
        # 3. Should have reasonable length (emails are typically 5-50 chars)
        if len(email) < 5 or len(email) > 50:
            continue
        
        # 4. Should not be mostly dots (more than 30% dots is suspicious)
        if email.count('.') / len(email) > 0.3:
            continue
        
        # 5. Local part (before @) should be reasonable
        local_part = email.split('@')[0] if '@' in email else ''
        if len(local_part) < 1 or len(local_part) > 30:
            continue
        
        # 6. Domain part (after @) should be reasonable
        if '@' in email:
            domain_part = email.split('@')[1]
            if '.' not in domain_part or len(domain_part) < 4:
                continue
        
        # 7. Prefer emails that look like valid dummy data (contains "dummy", "example", "test", etc.)
        # But still allow other reasonable-looking emails
        extracted["contact_info"].append({
            "type": "email",
            "value": email,
            "offset": match.start()
        })
    
    # Extract credit card numbers
    cc_pattern = r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}'
    for match in re.finditer(cc_pattern, cleaned_data):
        cc = match.group(0)
        if not any(p['value'] == cc for p in extracted["payment_info"] if p['type'] == 'credit_card'):
            extracted["payment_info"].append({
                "type": "credit_card",
                "value": cc,
                "offset": match.start()
            })
    
    return extracted

def format_leaked_data(leaked_data: str, max_display: int = 5000) -> dict:
    """Format leaked data for better display"""
    # Convert to bytes for proper handling
    try:
        leaked_bytes = leaked_data.encode('latin-1')  # Preserve all byte values
    except:
        leaked_bytes = leaked_data.encode('utf-8', errors='replace')
    
    if len(leaked_bytes) > max_display:
        displayed_bytes = leaked_bytes[:max_display]
        truncated = len(leaked_bytes) - max_display
    else:
        displayed_bytes = leaked_bytes
        truncated = 0
    
    # Create cleaned text version (readable characters only)
    displayed_clean = clean_text(leaked_data[:max_display] if len(leaked_data) > max_display else leaked_data)
    
    # Extract readable strings from cleaned version
    readable_strings = extract_readable_strings(displayed_clean, min_length=6)
    
    # Extract structured data
    structured_data = extract_structured_data(displayed_clean)
    
    # Find sensitive patterns in cleaned text
    sensitive_patterns = {
        "PRIVATE KEY": r'PRIVATE\s+KEY|BEGIN\s+PRIVATE\s+KEY',
        "SESSION_TOKEN": r'SESSION[_\s]?TOKEN|eyJ[A-Za-z0-9_-]+',
        "PASSWORD": r'PASSWORD|passwd|pwd',
        "API_KEY": r'API[_\s]?KEY|sk_live|sk_test',
        "CREDIT_CARD": r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',
        "EMAIL": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    }
    
    found_patterns = {}
    for name, pattern in sensitive_patterns.items():
        matches = list(re.finditer(pattern, displayed_clean, re.IGNORECASE))
        if matches:
            found_patterns[name] = matches
    
    # Create hex dump
    hex_dump = format_to_hex_dump(displayed_bytes)
    
    # Create readable memory dump (only printable characters, skip mostly unreadable lines)
    readable_dump_lines = []
    for i in range(0, len(displayed_clean), 80):
        chunk = displayed_clean[i:i+80]
        # Skip lines that are mostly dots (less than 20% readable characters)
        readable_chars = len([c for c in chunk if c != '.' and 32 <= ord(c) <= 126])
        if readable_chars > 16:  # At least 20% readable (16 out of 80)
            # Remove trailing dots for cleaner display
            chunk = chunk.rstrip('.')
            readable_dump_lines.append(f"{i:06d}: {chunk}")
    
    readable_dump = '\n'.join(readable_dump_lines) if readable_dump_lines else "No readable data in this range. Try increasing the payload length to leak more memory, or switch to 'Hex Dump' view to see all data."
    
    return {
        "displayed_raw": leaked_data[:max_display] if len(leaked_data) > max_display else leaked_data,
        "displayed_clean": displayed_clean,
        "displayed_bytes": displayed_bytes,
        "hex_dump": hex_dump,
        "readable_dump": readable_dump,
        "truncated": truncated,
        "readable_strings": readable_strings,
        "sensitive_patterns": found_patterns,
        "structured_data": structured_data,
        "total_length": len(leaked_data)
    }

# ============================================================================
# MAIN STREAMLIT APP
# ============================================================================

def main():
    st.title("Heartbleed Vulnerability Demonstration")
    st.markdown("---")
    
    # Sidebar with information
    with st.sidebar:
        st.header("About Heartbleed")
        st.markdown("""
        **CVE-2014-0160**
        
        The Heartbleed bug is a serious vulnerability in OpenSSL's 
        implementation of the TLS/DTLS heartbeat extension.
        
        **How it works:**
        1. Client sends a heartbeat request
        2. Server trusts the payload length field
        3. Server allocates buffer based on declared length
        4. Server leaks uninitialized memory (up to 64KB)
        """)
        
        st.markdown("---")
        st.header("⚠️ Important Notice")
        st.warning("""
        **All data in this demo is DUMMY/FAKE data for educational purposes only.**
        
        This is for educational purposes only. Do not use this technique on systems 
        you don't own or have permission to test.
        """)
        
        st.markdown("---")
        st.header("📚 Educational Value")
        st.info("""
        This demonstration helps understand:
        - How the Heartbleed vulnerability works
        - Why input validation is critical
        - How memory leaks can expose sensitive data
        - The importance of keeping software up-to-date
        """)
    
    # Main content area
    col1, col2 = st.columns(2)
    
    with col1:
        st.header("Send Heartbeat Request")
        st.markdown("""
        This simulates a heartbeat request from a client to the server.
        The **payload_length** field is what makes this vulnerable - the server
        trusts this value without proper validation.
        """)
        
        # Input fields
        payload = st.text_input(
            "Payload (actual data to send)",
            value="Hello",
            help="The actual payload data. Try making this small while increasing the payload_length to see the vulnerability!"
        )
        
        # Text input for payload length instead of slider
        payload_length_input = st.text_input(
            "Payload Length (declared)",
            value=str(len(payload) if payload else 1),
            help="This is the vulnerable part! The server trusts this value. Try setting it much higher than the actual payload size (e.g., 10000)."
        )
        
        # Validate and convert payload_length
        try:
            payload_length = int(payload_length_input)
            if payload_length < 1:
                st.error("Payload length must be at least 1")
                payload_length = 1
            elif payload_length > 65536:
                st.warning("Payload length exceeds maximum (65536). Using 65536.")
                payload_length = 65536
        except ValueError:
            st.error("Please enter a valid number for payload length")
            payload_length = len(payload) if payload else 1
        
        actual_size = len(payload.encode('utf-8'))
        st.info(f"Actual payload size: **{actual_size} bytes**")
        
        if payload_length > actual_size:
            leak_size = payload_length - actual_size
            st.warning(f"Declared length ({payload_length:,} bytes) is larger than actual payload ({actual_size} bytes). This will trigger the vulnerability!")
            st.error(f"Potential memory leak: **{leak_size:,} bytes**")
        elif payload_length == actual_size:
            st.success("Payload length matches actual size. No vulnerability triggered.")
        else:
            st.info("Declared length is smaller than actual payload. Server should reject this.")
        
        # Send button
        if st.button("Send Heartbeat Request", type="primary", use_container_width=True):
            with st.spinner("Sending heartbeat request..."):
                result = process_heartbeat(payload, payload_length)
                
                if result:
                    st.session_state['heartbeat_result'] = result
                    st.session_state['requested_payload_length'] = payload_length
                    st.rerun()
    
    with col2:
        st.header("Server Response")
        
        if 'heartbeat_result' in st.session_state:
            result = st.session_state['heartbeat_result']
            requested_length = st.session_state.get('requested_payload_length', result['actual_length'])
            
            st.success("Heartbeat response received!")
            
            # Statistics
            col_stat1, col_stat2, col_stat3 = st.columns(3)
            with col_stat1:
                st.metric("Actual Payload", f"{result['actual_length']:,} bytes")
            with col_stat2:
                st.metric("Declared Length", f"{requested_length:,} bytes")
            with col_stat3:
                st.metric("Leaked Bytes", f"{result['leaked_bytes']:,} bytes", delta=f"+{result['leaked_bytes']:,}")
            
            # Highlight leaked data
            if result['leaked_bytes'] > 0:
                st.markdown("---")
                leaked_data = result['response'][result['actual_length']:]
                formatted_data = format_leaked_data(leaked_data)
                
                st.subheader("Leaked Memory Data")
                st.info("⚠️ **Note:** All leaked data shown is DUMMY/FAKE data for educational demonstration only.")
                st.markdown(f"**Total leaked:** {formatted_data['total_length']:,} bytes")
                if formatted_data['truncated'] > 0:
                    displayed_size = formatted_data['total_length'] - formatted_data['truncated']
                    st.info(f"Showing first {displayed_size:,} bytes (truncated {formatted_data['truncated']:,} bytes)")
                
                # Display options
                view_mode = st.radio("View mode", ["Extracted Data", "Readable Only", "Hex Dump", "Readable Strings", "Raw"], horizontal=True)
                
                if view_mode == "Extracted Data":
                    # Show extracted structured data
                    st.markdown("### Extracted Sensitive Data")
                    st.caption("Structured data extracted from leaked memory. This shows what an attacker could extract from the vulnerability. **All data is DUMMY/FAKE for educational purposes.**")
                    
                    structured = formatted_data['structured_data']
                    has_data = any(structured.values())
                    
                    if not has_data:
                        st.warning("No structured data found in the leaked memory. Try increasing the payload length to leak more memory.")
                        st.info("The backend contains dummy sensitive data like private keys, credentials, API keys, and more. Increase the leak size to extract them.")
                    else:
                        # Private Keys
                        if structured["private_keys"]:
                            st.markdown("#### Private Keys")
                            st.caption("⚠️ **DUMMY KEY** - This is fake data for demonstration only")
                            for idx, key_data in enumerate(structured["private_keys"], 1):
                                with st.expander(f"Private Key #{idx} (Offset: {key_data['offset']:,}, Length: {key_data['length']:,} bytes)"):
                                    st.code(key_data['content'], language="text")
                            st.markdown("")
                        
                        # Credentials
                        if structured["credentials"]:
                            st.markdown("#### Credentials")
                            st.caption("⚠️ **DUMMY CREDENTIALS** - All data is fake for demonstration only")
                            cred_col1, cred_col2 = st.columns(2)
                            for idx, cred in enumerate(structured["credentials"]):
                                col = cred_col1 if idx % 2 == 0 else cred_col2
                                with col:
                                    st.text_input(
                                        f"{cred['type'].title()} (Offset: {cred['offset']:,})",
                                        value=cred['value'],
                                        key=f"cred_{cred['offset']}",
                                        disabled=True
                                    )
                            st.markdown("")
                        
                        # API Keys
                        if structured["api_keys"]:
                            st.markdown("#### API Keys & Secrets")
                            st.caption("⚠️ **DUMMY API KEYS** - All data is fake for demonstration only")
                            for idx, key_data in enumerate(structured["api_keys"], 1):
                                st.text_input(
                                    f"{key_data['type'].replace('_', ' ').title()} (Offset: {key_data['offset']:,})",
                                    value=key_data['value'],
                                    key=f"api_{key_data['offset']}",
                                    disabled=True,
                                    type="password"
                                )
                            st.markdown("")
                        
                        # Tokens
                        if structured["tokens"]:
                            st.markdown("#### Tokens")
                            st.caption("⚠️ **DUMMY TOKENS** - All data is fake for demonstration only")
                            for idx, token_data in enumerate(structured["tokens"], 1):
                                with st.expander(f"{token_data['type'].replace('_', ' ').title()} #{idx} (Offset: {token_data['offset']:,})"):
                                    st.code(token_data['value'], language="text")
                                    if len(token_data['value']) > 50:
                                        st.caption(f"Full token (truncated in preview): {len(token_data['value'])} characters")
                            st.markdown("")
                        
                        # Payment Information
                        if structured["payment_info"]:
                            st.markdown("#### Payment Information")
                            st.caption("⚠️ **DUMMY PAYMENT INFO** - All data is fake (e.g., 0000-0000-0000-0000) for demonstration only")
                            payment_col1, payment_col2 = st.columns(2)
                            for idx, payment in enumerate(structured["payment_info"]):
                                col = payment_col1 if idx % 2 == 0 else payment_col2
                                with col:
                                    st.text_input(
                                        f"{payment['type'].replace('_', ' ').title()} (Offset: {payment['offset']:,})",
                                        value=payment['value'],
                                        key=f"payment_{payment['offset']}",
                                        disabled=True,
                                        type="password" if payment['type'] == 'cvv' else "default"
                                    )
                            st.markdown("")
                        
                        # Database Information
                        if structured["database_info"]:
                            st.markdown("#### Database Information")
                            st.caption("⚠️ **DUMMY DATABASE INFO** - All data is fake for demonstration only")
                            for idx, db_data in enumerate(structured["database_info"], 1):
                                st.text_input(
                                    f"{db_data['type'].replace('_', ' ').title()} (Offset: {db_data['offset']:,})",
                                    value=db_data['value'],
                                    key=f"db_{db_data['offset']}",
                                    disabled=True,
                                    type="password" if 'password' in db_data['type'].lower() else "default"
                                )
                            st.markdown("")
                        
                        # Contact Information
                        if structured["contact_info"]:
                            st.markdown("#### Contact Information")
                            st.caption("⚠️ **DUMMY CONTACT INFO** - All data is fake for demonstration only")
                            contact_col1, contact_col2 = st.columns(2)
                            for idx, contact in enumerate(structured["contact_info"]):
                                col = contact_col1 if idx % 2 == 0 else contact_col2
                                with col:
                                    st.text_input(
                                        f"{contact['type'].title()} (Offset: {contact['offset']:,})",
                                        value=contact['value'],
                                        key=f"contact_{contact['offset']}",
                                        disabled=True
                                    )
                            st.markdown("")
                        
                        # Other
                        if structured["other"]:
                            st.markdown("#### Other Sensitive Data")
                            st.caption("⚠️ **DUMMY DATA** - All data is fake for demonstration only")
                            for idx, other_data in enumerate(structured["other"], 1):
                                with st.expander(f"{other_data['type'].replace('_', ' ').title()} #{idx} (Offset: {other_data['offset']:,})"):
                                    st.code(other_data['value'], language="text")
                            st.markdown("")
                        
                        # Summary
                        total_extracted = sum(len(items) for items in structured.values())
                        st.success(f"**Extracted {total_extracted} piece(s) of sensitive data from leaked memory!**")
                
                elif view_mode == "Readable Only":
                    # Show only readable content
                    st.markdown("### Memory Dump (Readable Characters Only)")
                    st.caption("Non-printable characters are replaced with dots (.). Only readable ASCII content is shown.")
                    st.info("⚠️ **Note:** All data shown is DUMMY/FAKE for educational demonstration only.")
                    
                    # Show sensitive patterns first
                    if formatted_data['sensitive_patterns']:
                        st.markdown("#### Detected Sensitive Data")
                        for pattern_name, matches in formatted_data['sensitive_patterns'].items():
                            st.markdown(f"**{pattern_name}** - Found {len(matches)} occurrence(s):")
                            for i, match in enumerate(matches[:5]):  # Show first 5
                                start = max(0, match.start() - 50)
                                end = min(len(formatted_data['displayed_clean']), match.end() + 50)
                                context = formatted_data['displayed_clean'][start:end]
                                # Clean up the context - remove leading/trailing dots
                                context = context.strip('.')
                                if context:
                                    # Highlight the match in bold
                                    match_text = match.group()
                                    highlighted = context.replace(match_text, f"**{match_text}**")
                                    st.markdown(f"  • {highlighted}")
                            if len(matches) > 5:
                                st.caption(f"  ... and {len(matches) - 5} more occurrence(s)")
                            st.markdown("")
                    
                    # Show readable memory dump
                    if formatted_data['readable_dump'] and formatted_data['readable_dump'] != "No readable data in this range.":
                        st.markdown("#### Readable Memory Content")
                        st.text_area(
                            "Memory dump (readable only)", 
                            value=formatted_data['readable_dump'], 
                            height=400, 
                            label_visibility="collapsed"
                        )
                    else:
                        st.info("No readable ASCII characters found in this memory range.")
                    
                    # Show readable strings separately
                    if formatted_data['readable_strings']:
                        st.markdown("#### Extracted Readable Strings")
                        readable_count = min(30, len(formatted_data['readable_strings']))
                        strings_display = []
                        for string, pos in formatted_data['readable_strings'][:readable_count]:
                            # Truncate very long strings
                            display_string = string[:200] + '...' if len(string) > 200 else string
                            strings_display.append(f"[Offset {pos:,}] {display_string}")
                        
                        st.text_area(
                            "Readable strings",
                            value='\n'.join(strings_display),
                            height=200,
                            label_visibility="collapsed"
                        )
                        if len(formatted_data['readable_strings']) > readable_count:
                            st.caption(f"... and {len(formatted_data['readable_strings']) - readable_count} more readable strings")
                    
                elif view_mode == "Hex Dump":
                    st.markdown("### Memory Dump (Hex Format)")
                    st.caption("Standard hex dump format: offset | hex bytes | ASCII representation")
                    st.info("⚠️ **Note:** All data shown is DUMMY/FAKE for educational demonstration only.")
                    st.text_area(
                        "Hex dump",
                        value=formatted_data['hex_dump'],
                        height=400,
                        label_visibility="collapsed"
                    )
                    
                elif view_mode == "Readable Strings":
                    st.markdown("### Extracted Readable Strings Only")
                    st.caption("Only sequences of readable ASCII characters (6+ characters) are shown.")
                    st.info("⚠️ **Note:** All data shown is DUMMY/FAKE for educational demonstration only.")
                    if formatted_data['readable_strings']:
                        strings_text = "\n\n".join([
                            f"Offset {pos:,}:\n{string}" 
                            for string, pos in formatted_data['readable_strings']
                        ])
                        st.text_area(
                            "Readable strings",
                            value=strings_text,
                            height=400,
                            label_visibility="collapsed"
                        )
                        st.info(f"Found {len(formatted_data['readable_strings'])} readable string(s)")
                    else:
                        st.info("No readable strings found in the leaked data.")
                        st.markdown("Try increasing the payload length to leak more memory.")
                    
                elif view_mode == "Raw":
                    st.markdown("### Memory Dump (Raw - All Characters)")
                    st.warning("This view shows all data including non-printable characters. It may appear garbled.")
                    st.info("⚠️ **Note:** All data shown is DUMMY/FAKE for educational demonstration only.")
                    st.text_area(
                        "Raw leaked data",
                        value=formatted_data['displayed_clean'],
                        height=400,
                        label_visibility="collapsed"
                    )
                
                # Sensitive data summary
                if formatted_data['sensitive_patterns']:
                    st.markdown("---")
                    st.subheader("Security Alert")
                    pattern_names = list(formatted_data['sensitive_patterns'].keys())
                    st.error(f"**Warning:** Detected {len(pattern_names)} type(s) of sensitive data: {', '.join(pattern_names)}")
                    st.markdown("This demonstrates how the Heartbleed vulnerability can expose confidential information stored in server memory.")
        else:
            st.info("Send a heartbeat request to see the server response here.")
            st.markdown("""
            **Try this:**
            1. Set payload to "test"
            2. Set payload_length to 10000
            3. Click "Send Heartbeat Request"
            4. Watch the leaked data appear!
            
            **Note:** All leaked data will be DUMMY/FAKE data for educational purposes.
            """)
    
    # Explanation section
    st.markdown("---")
    st.header("How the Vulnerability Works")
    
    col_exp1, col_exp2 = st.columns(2)
    
    with col_exp1:
        st.subheader("Normal (Secure) Behavior")
        st.markdown("""
        In a secure implementation:
        - Server validates that payload_length matches actual payload size
        - Server only returns the actual payload
        - No memory is leaked
        """)
        st.code("""
        if (payload_length != actual_payload_size) {
            return ERROR;
        }
        return payload;
        """, language="c")
    
    with col_exp2:
        st.subheader("Vulnerable (Heartbleed) Behavior")
        st.markdown("""
        In the vulnerable implementation:
        - Server trusts the payload_length field
        - Server allocates buffer of size payload_length
        - Server copies payload and fills rest with uninitialized memory
        - Server returns the entire buffer (leaking memory)
        """)
        st.code("""
        buffer = malloc(payload_length);  // Trust client!
        memcpy(buffer, payload, payload_size);
        // Rest of buffer contains uninitialized memory
        return buffer;  // Leak!
        """, language="c")
    
    # Technical details
    with st.expander("Technical Details"):
        st.markdown("""
        **The Heartbleed Bug (CVE-2014-0160)**
        
        - **Affected**: OpenSSL versions 1.0.1 through 1.0.1f
        - **Discovery**: April 2014
        - **Severity**: Critical
        - **Impact**: Allows reading up to 64KB of server memory per request
        
        **The Vulnerability:**
        
        The bug was in OpenSSL's implementation of the TLS heartbeat extension.
        The server would allocate a buffer based on the `payload_length` field in
        the heartbeat request, but didn't validate that this length matched the
        actual payload size. This allowed attackers to request a large buffer
        (up to 64KB) while sending a small payload, causing the server to return
        uninitialized memory containing potentially sensitive data.
        
        **What can be leaked:**
        - Private keys
        - Session tokens
        - Passwords
        - Credit card numbers
        - Other sensitive data in server memory
        
        **Fix:**
        - Validate that payload_length matches actual payload size
        - Only return the actual payload, not uninitialized memory
        
        **Important Note:**
        - All data in this demonstration is DUMMY/FAKE data for educational purposes only
        - This demo does not use real credentials or sensitive information
        - In a real Heartbleed attack, actual server memory would be leaked
        """)

if __name__ == "__main__":
    main()

