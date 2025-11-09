# Heartbleed Vulnerability Demonstration

A web application demonstrating the Heartbleed vulnerability (CVE-2014-0160) using Streamlit. All data is **DUMMY/FAKE** for educational purposes and safe for public repositories.

## ⚠️ Important Notice

**All data in this demo is DUMMY/FAKE data for educational purposes only.**
- All credentials, keys, tokens, and sensitive data are fake
- Credit card numbers are dummy (e.g., 0000-0000-0000-0000)
- Email addresses are dummy (e.g., dummy@example.com)
- This demo is safe to deploy to public repositories

This is for **educational purposes only**. Do not use this technique on systems you don't own or have permission to test.

## Overview

This application simulates the Heartbleed bug, a critical vulnerability in OpenSSL's implementation of the TLS/DTLS heartbeat extension. The demo allows users to:

- Send heartbeat requests with customizable payload lengths
- Observe how the server leaks memory when it trusts the client-provided length field
- See how sensitive data can be extracted from leaked memory
- Understand the importance of input validation

## Features

- **Single-file deployment** - Everything in one `app.py` file
- **No backend server required** - Integrated backend logic
- **Safe for public repos** - All data is dummy/fake
- **Multiple view modes** for leaked memory data:
  - Extracted structured data (private keys, credentials, tokens, etc.)
  - Readable-only view with sensitive pattern detection
  - Hex dump format
  - Readable strings extraction
  - Raw data view
- **Educational information** about the vulnerability

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone or download this repository

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Running Locally

### Simple Startup

Run the Streamlit app:
```bash
streamlit run app.py
```

The app will start on `http://localhost:8501` (or another port if 8501 is occupied)

Open your web browser and navigate to the URL shown in the terminal.

## Deployment to Streamlit Cloud

This app is ready to deploy to Streamlit Cloud:

1. **Push to GitHub**: Push this repository to a public GitHub repository

2. **Deploy on Streamlit Cloud**:
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Sign in with your GitHub account
   - Click "New app"
   - Select your repository
   - Set Main file path to: `app.py`
   - Click "Deploy"

3. **Your app will be live!** Streamlit Cloud will automatically handle:
   - Installing dependencies from `requirements.txt`
   - Running the app
   - Providing a public URL

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
├── app.py              # Single-file Streamlit application (frontend + backend)
├── requirements.txt    # Python dependencies (only streamlit)
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

## References

- [CVE-2014-0160](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160)
- [Heartbleed Bug](https://heartbleed.com/)
- [OpenSSL Security Advisory](https://www.openssl.org/news/secadv/20140407.txt)

## Dependencies

The project uses only one Python package:
- `streamlit` - Frontend UI framework and server

See `requirements.txt` for details.

## Technical Notes

- The backend logic is integrated into the Streamlit app (no separate server needed)
- The app simulates the Heartbleed vulnerability by trusting the client-provided `payload_length` field
- Dummy sensitive data is distributed throughout a 64KB memory buffer at various offsets
- The maximum leak size is 65,536 bytes (64KB), matching the real Heartbleed vulnerability
- The frontend automatically extracts and categorizes sensitive data from leaked memory
- All extracted data is clearly marked as dummy/fake

## Troubleshooting

### App not starting
- Ensure Streamlit is installed: `pip install streamlit`
- Check that port 8501 is not already in use
- Try accessing a different port: `streamlit run app.py --server.port 8502`

### No leaked data appearing
- Ensure the `payload_length` is larger than the actual payload size
- Try increasing the payload length (e.g., 10000 or higher)
- Check the browser console for any errors

### Deployment issues on Streamlit Cloud
- Ensure `requirements.txt` is in the root directory
- Verify that `app.py` is the main file
- Check that all dependencies are listed in `requirements.txt`
- Review Streamlit Cloud logs for error messages

## License

This project is for educational purposes only.
