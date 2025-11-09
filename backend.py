from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import random
import string

app = FastAPI(title="Heartbleed Vulnerability Demo Backend")

# Enable CORS for Streamlit
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# DUMMY SENSITIVE DATA - For Educational Demonstration Only
# All data is fake and does not represent real credentials or sensitive information
# ============================================================================

SENSITIVE_DATA = {
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

class HeartbeatRequest(BaseModel):
    payload: str
    payload_length: int  # This is the vulnerable part - client controls this

class HeartbeatResponse(BaseModel):
    response: str
    actual_length: int
    leaked_bytes: int

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
        bytes(SENSITIVE_DATA["private_key"], "utf-8") + b"\n",
        b"=== PRIVATE KEY END ===\n",
        
        b"SESSION_TOKEN: " + bytes(SENSITIVE_DATA["session_token"], "utf-8") + b"\n",
        b"PASSWORD: " + bytes(SENSITIVE_DATA["password"], "utf-8") + b"\n",
        b"USERNAME: " + bytes(SENSITIVE_DATA["username"], "utf-8") + b"\n",
        
        b"API_KEY: " + bytes(SENSITIVE_DATA["api_key"], "utf-8") + b"\n",
        b"SECRET_KEY: " + bytes(SENSITIVE_DATA["secret_key"], "utf-8") + b"\n",
        
        b"CREDIT_CARD: " + bytes(SENSITIVE_DATA["credit_card"], "utf-8") + b"\n",
        b"CVV: " + bytes(SENSITIVE_DATA["cvv"], "utf-8") + b"\n",
        b"EXPIRY: " + bytes(SENSITIVE_DATA["expiry"], "utf-8") + b"\n",
        
        b"DATABASE_URL: " + bytes(SENSITIVE_DATA["database_url"], "utf-8") + b"\n",
        b"REDIS_PASSWORD: " + bytes(SENSITIVE_DATA["redis_password"], "utf-8") + b"\n",
        
        b"EMAIL: " + bytes(SENSITIVE_DATA["email"], "utf-8") + b"\n",
        b"PHONE: " + bytes(SENSITIVE_DATA["phone"], "utf-8") + b"\n",
        
        b"SSH_KEY: " + bytes(SENSITIVE_DATA["ssh_key"], "utf-8") + b"\n",
        b"OAUTH_TOKEN: " + bytes(SENSITIVE_DATA["oauth_token"], "utf-8") + b"\n",
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

@app.get("/")
async def root():
    return {"message": "Heartbleed Vulnerability Demo Backend", "status": "running"}

@app.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(request: HeartbeatRequest):
    """
    VULNERABLE HEARTBEAT ENDPOINT - This mimics the Heartbleed vulnerability.
    
    The vulnerability: The server trusts the payload_length field from the client
    without properly validating it against the actual payload size.
    
    In the real Heartbleed bug, OpenSSL would:
    1. Allocate a buffer based on payload_length (up to 64KB)
    2. Copy the payload (which might be smaller)
    3. Return the buffer, which includes uninitialized memory (the leak)
    """
    actual_payload_size = len(request.payload.encode('utf-8'))
    
    # VULNERABILITY: Server trusts client-provided payload_length
    # without validating it matches the actual payload size
    declared_length = request.payload_length
    
    # Simulate the vulnerable behavior
    # Allocate buffer based on declared length (up to 64KB)
    max_length = min(declared_length, 65536)  # Max 64KB like in Heartbleed
    
    # Create response buffer
    response_buffer = bytearray(max_length)
    
    # Copy the actual payload (which might be smaller)
    payload_bytes = request.payload.encode('utf-8')
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
    leaked_data = response_buffer[payload_size:max_length].decode('utf-8', errors='ignore')
    response_data = response_buffer[:max_length].decode('utf-8', errors='ignore')
    
    leaked_bytes = max_length - payload_size
    
    return HeartbeatResponse(
        response=response_data,
        actual_length=actual_payload_size,
        leaked_bytes=leaked_bytes
    )

@app.get("/info")
async def info():
    """
    Information endpoint explaining the vulnerability
    """
    return {
        "vulnerability": "Heartbleed (CVE-2014-0160)",
        "description": "The Heartbleed bug allows an attacker to read up to 64KB of memory from the server",
        "how_it_works": [
            "Client sends a heartbeat request with a payload and a payload_length field",
            "The server trusts the payload_length without validating it matches the actual payload",
            "Server allocates a buffer of size payload_length",
            "Server copies the payload (which might be smaller) and fills the rest with uninitialized memory",
            "Server sends back the entire buffer, leaking sensitive data"
        ],
        "max_leak_size": "65536 bytes (64KB)",
        "note": "This is a demonstration. Real Heartbleed affected OpenSSL versions 1.0.1 through 1.0.1f"
    }

