# MaliciousProxy

A lightweight, asynchronous HTTP/HTTPS man-in-the-middle (MITM) interception proxy written in Python using asyncio and the modern cryptography library. This framework is designed for security research, vulnerability analysis, and understanding how transparent traffic interception and dynamic payload injection operate.

- Asynchronous Architecture: Built on top of Python's asyncio streams to handle hundreds of concurrent browser sessions simultaneously without blocking.

- Dynamic TLS Interception: Generates on-the-fly, site-specific X.509 certificates for HTTPS domains using a custom local Root CA.

TODO

- Modern PKI Compliance: Automatically adds mandatory Subject Alternative Name (SAN) extensions and unique, randomized serial numbers to satisfy strict modern browser validation (Firefox, Chromium/Brave).

- Payload Injection Engine: Automatically inspects content streams and transparently injects custom JavaScript hooks into targeted HTML responses.

- Secure by Design Workflows: Avoids tracking or staging raw secret artifacts in version control via strict Git environment configurations.

## Directory Structure

```
MaliciousProxy/
├── core/                   # The engine: handling sockets and SSL
│   ├── sniffer.py          # Packet capture and protocol identification
│   ├── interceptor.py      # Main proxy logic (Request/Response modification)
│   └── cert_manager.py     # On-the-fly SSL certificate generation
├── payloads/               # Modular "attacks"
│   ├── inject_js.py        # Logic to find </body> and inject hooks
│   ├── ssl_strip.py        # Logic to downgrade HTTPS to HTTP
│   └── cred_harvester.py   # Target-specific scrapers
├── static/                 # The "Malicious" client-side code
│   ├── hook.js             # The JS injected into victim browsers
│   └── logger.ts           # TypeScript for data processing before exfiltration
├── c2_server/              # Command & Control (The "home base")
│   ├── app.py              # Flask/FastAPI to receive exfiltrated data
│   └── dashboard.html      # UI to view captured tokens/credentials
├── tests/                  # Lab validation
│   └── test_mitm.py        # Unit tests for interception logic
└── README.md               # Documentation 
```

## Disclaimer
This software framework is developed strictly for educational purposes and authorized penetration testing methodologies. Do not execute this code against environments or networks without explicit, written compliance authorization. The author accepts zero liability for misuse or destructive operations using this application framework.
