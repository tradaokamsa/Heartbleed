# Heartbleed Vulnerability Demonstration

A friendly web application demonstrating the Heartbleed vulnerability (CVE-2014-0160) using Streamlit for the UI and FastAPI for the backend.

## Overview

This application simulates the Heartbleed bug, a critical vulnerability in OpenSSL's implementation of the TLS/DTLS heartbeat extension. The demo allows users to:

- Send heartbeat requests with customizable payload lengths
- Observe how the server leaks memory when it trusts the client-provided length field
- See how sensitive data can be extracted from leaked memory

## ⚠️ Warning

This is for **educational purposes only**. Do not use this technique on systems you don't own or have permission to test.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone or download this repository

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

### Step 1: Start the Backend Server

Open a terminal and run:
```bash
uvicorn backend:app --reload
```

The backend will start on `http://localhost:8000`

### Step 2: Start the Frontend (Streamlit)

Open another terminal and run:
```bash
streamlit run frontend.py
```

The frontend will start on `http://localhost:8501` (or another port if 8501 is occupied)

### Step 3: Access the Application

Open your web browser and navigate to the URL shown in the Streamlit terminal (usually `http://localhost:8501`)

## How to Use

1. **Normal Operation**: 
   - Set a payload (e.g., "Hello")
   - Set the payload length to match the actual payload size
   - Click "Send Heartbeat Request"
   - Observe that only the payload is returned

2. **Exploiting the Vulnerability**:
   - Set a small payload (e.g., "test")
   - Set the payload length to a much larger value (e.g., 10000)
   - Click "Send Heartbeat Request"
   - Observe that the server returns the payload PLUS leaked memory data
   - Check the "Leaked Memory Data" section to see what was extracted
   - Look for sensitive data patterns in the leaked data

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
heartbleed/
├── backend.py          # FastAPI backend with vulnerable heartbeat endpoint
├── frontend.py         # Streamlit frontend UI
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## API Endpoints

### `GET /`
Health check endpoint

### `POST /heartbeat`
Vulnerable heartbeat endpoint that mimics the Heartbleed bug

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
Information about the vulnerability

## Educational Value

This demonstration helps understand:
- How the Heartbleed vulnerability works
- Why input validation is critical
- How memory leaks can expose sensitive data
- The importance of keeping software up-to-date

## References

- [CVE-2014-0160](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160)
- [Heartbleed Bug](https://heartbleed.com/)
- [OpenSSL Security Advisory](https://www.openssl.org/news/secadv/20140407.txt)

## License

This project is for educational purposes only.

