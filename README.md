# Heartbleed Vulnerability Demonstration

A web application demonstrating the Heartbleed vulnerability (CVE-2014-0160) using Streamlit. All data is **DUMMY/FAKE** for educational purposes.

This is for **educational purposes only**. Do not use this technique on systems you don't own or have permission to test.

## Overview

This application simulates the Heartbleed bug, a critical vulnerability in OpenSSL's implementation of the TLS/DTLS heartbeat extension. The demo allows users to:

- Send heartbeat requests with customizable payload lengths
- Observe how the server leaks memory when it trusts the client-provided length field
- See how sensitive data can be extracted from leaked memory
- Understand the importance of input validation

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone or download this repository

2. Install the required dependencies:

**For single-file deployment (app.py):**
```bash
pip install -r requirements.txt
```

**For separate frontend/backend deployment:**
```bash
pip install streamlit fastapi uvicorn requests pydantic
```

## Running Locally

### Option 1: Single-File Deployment (Recommended for Streamlit Cloud)

Run the standalone Streamlit app:
```bash
streamlit run app.py
```

The app will start on `http://localhost:8501` (or another port if 8501 is occupied)

### Option 2: Separate Frontend/Backend Deployment

#### Step 1: Start the Backend Server

**Using the start script:**
```bash
chmod +x start_backend.sh
./start_backend.sh
```

**Or manually:**
```bash
uvicorn backend:app --reload --host 0.0.0.0 --port 8000
```

The backend will start on `http://localhost:8000`
- API will be available at: `http://localhost:8000`
- API documentation (Swagger UI) will be available at: `http://localhost:8000/docs`

#### Step 2: Start the Frontend (Streamlit)

**Using the start script:**
```bash
chmod +x start_frontend.sh
./start_frontend.sh
```

**Or manually:**
```bash
streamlit run frontend.py
```

The frontend will start on `http://localhost:8501` (or another port if 8501 is occupied)

#### Step 3: Access the Application

Open your web browser and navigate to the URL shown in the Streamlit terminal (usually `http://localhost:8501`)

## How to Use

### Normal Operation (No Vulnerability)

1. Set a payload (e.g., "Hello")
2. Set the payload length to match the actual payload size (e.g., 5)
3. Click "Send Heartbeat Request"
4. Observe that only the payload is returned
5. No memory leak occurs when lengths match

### Exploiting the Vulnerability

1. Set a small payload (e.g., "test")
2. Set the payload length to a much larger value (e.g., 10000)
3. Click "Send Heartbeat Request"
4. Observe that the server returns the payload PLUS leaked memory data
5. Check the "Leaked Memory Data" section to see what was extracted
6. The frontend provides multiple view modes:
   - **Extracted Data**: Shows structured sensitive data (private keys, credentials, API keys, tokens, payment info, etc.)
   - **Readable Only**: Displays only readable ASCII characters with detected sensitive patterns
   - **Hex Dump**: Shows memory dump in standard hex format
   - **Readable Strings**: Lists extracted readable strings from the leaked memory
   - **Raw**: Shows all leaked data including non-printable characters

### Tips for Best Results

- Start with a small payload length (e.g., 1000) and gradually increase it
- Larger payload lengths (e.g., 50000-65536) will leak more memory and reveal more sensitive data
- The backend simulates dummy sensitive data scattered throughout memory at various offsets
- Try multiple requests with different payload lengths to extract different portions of memory
- All extracted data is validated and filtered to show clean, readable dummy data

## How the Vulnerability Works

### The Heartbleed Bug

The Heartbleed vulnerability (CVE-2014-0160) affected OpenSSL versions 1.0.1 through 1.0.1f. The bug allowed an attacker to read up to 64KB of memory from the server or client.

### The Attack Vector

1. **Client sends heartbeat request**: The client sends a heartbeat request with:
   - A payload (the actual data)
   - A `payload_length` field (declaring the size of the payload)

2. **Server trusts the length field**: The vulnerable server allocates a buffer based on the `payload_length` field without validating that it matches the actual payload size.

3. **Memory leak**: The server:
   - Allocates a buffer of size `payload_length` (up to 64KB)
   - Copies the actual payload (which might be much smaller)
   - Fills the rest of the buffer with uninitialized memory
   - Returns the entire buffer to the client

4. **Data extraction**: The attacker receives the leaked memory, which may contain:
   - Private keys
   - Session tokens
   - Passwords
   - Credit card numbers
   - Other sensitive data

### The Fix

A secure implementation should:
- Validate that `payload_length` matches the actual payload size
- Reject requests where the lengths don't match
- Only return the actual payload, not uninitialized memory

## Project Structure

```
Heartbleed/
├── app.py              # Single-file Streamlit application (frontend + backend) - for Streamlit Cloud
├── frontend.py         # Streamlit frontend UI (for separate deployment)
├── backend.py          # FastAPI backend server (for separate deployment)
├── requirements.txt    # Python dependencies (for app.py)
├── start_backend.sh    # Shell script to start the backend server
├── start_frontend.sh   # Shell script to start the frontend
├── README.md          # This file
└── .gitignore         # Git ignore file
```

## Dummy Data

All sensitive data in this demo is **DUMMY/FAKE** for educational purposes:

- **Private Keys**: Dummy RSA keys with note that they're fake
- **Credentials**: Dummy usernames and passwords (e.g., "dummy_user", "dummy_password_12345")
- **API Keys**: Dummy keys with "test" or "000000" patterns
- **Tokens**: Dummy JWT tokens with "DUMMY_TOKEN" markers
- **Credit Cards**: Dummy numbers (0000-0000-0000-0000)
- **Emails**: Dummy emails (dummy@example.com)
- **Phone Numbers**: Dummy numbers (+1-555-000-0000)
- **Database URLs**: Dummy connection strings

All data is clearly marked as dummy/fake throughout the application.

## Educational Value

This demonstration helps understand:
- How the Heartbleed vulnerability works in practice
- Why input validation is critical for security
- How memory leaks can expose sensitive data
- The importance of keeping software up-to-date
- How attackers can extract confidential information from server memory
- The impact of trusting client-provided data without validation
- Real-world consequences of memory disclosure vulnerabilities

## API Endpoints (Backend Only)

When using the separate frontend/backend deployment:

### `GET /`
Health check endpoint that returns the status of the backend server.

**Response:**
```json
{
    "message": "Heartbleed Vulnerability Demo Backend",
    "status": "running"
}
```

### `POST /heartbeat`
Vulnerable heartbeat endpoint that mimics the Heartbleed bug.

**Request:**
```json
{
    "payload": "test",
    "payload_length": 10000
}
```

**Response:**
```json
{
    "response": "test...<leaked memory data>...",
    "actual_length": 4,
    "leaked_bytes": 9996
}
```

### `GET /info`
Information endpoint that provides details about the vulnerability.

## Technical Notes

- **Single-file deployment**: The backend logic is integrated into the Streamlit app (no separate server needed)
- **Separate deployment**: Frontend connects to FastAPI backend via HTTP requests
- The app simulates the Heartbleed vulnerability by trusting the client-provided `payload_length` field
- Dummy sensitive data is distributed throughout a 64KB memory buffer at various offsets
- Data is separated with newlines for better extraction
- The maximum leak size is 65,536 bytes (64KB), matching the real Heartbleed vulnerability
- The frontend automatically extracts and categorizes sensitive data from leaked memory
- All extracted data is validated and filtered to show clean, readable dummy data
- All extracted data is clearly marked as dummy/fake

## References

- [CVE-2014-0160](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160)
- [Heartbleed Bug](https://heartbleed.com/)
- [OpenSSL Security Advisory](https://www.openssl.org/news/secadv/20140407.txt)
