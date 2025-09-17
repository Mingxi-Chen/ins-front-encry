# Instagram Password Encryption Tool

A Node.js implementation of Instagram's client-side password encryption mechanism used in their web login process. This tool replicates the encryption algorithm that Instagram uses to secure passwords before transmission to their servers.

## Overview

Instagram uses a sophisticated encryption scheme called "PolarisEnvelopeEncryption" to encrypt user passwords on the client side before sending them to the server. This tool implements the same encryption algorithm, allowing you to generate encrypted passwords in the same format that Instagram's web interface uses.

## Features

- **AES-256-GCM Encryption**: Uses industry-standard AES-256-GCM encryption for password security
- **Curve25519 Sealed Box**: Implements Curve25519 sealed box encryption for key exchange
- **Instagram-Compatible Format**: Generates passwords in the exact format Instagram expects (`#PWD_INSTAGRAM_BROWSER:version:timestamp:base64payload`)
- **Configurable Parameters**: Supports custom key IDs, public keys, versions, and timestamps
- **CLI Interface**: Easy-to-use command-line interface for password encryption

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   npm install
   ```

## Dependencies

- `tweetnacl`: Pure JavaScript implementation of the NaCl cryptographic library
- `tweetnacl-sealedbox-js`: JavaScript implementation of NaCl sealed box encryption

## Usage

### Basic Usage

```bash
node encrypt_cli.js --password 'YourPassword123'
```

### Advanced Usage

```bash
node encrypt_cli.js -p 'YourPassword123' --ts 1757900872
node encrypt_cli.js -p 'YourPassword123' --key-id 78 --pub f8c86a4d0d92f87c01b9fb26aca4d60acf67f6fb517c28974d8e2b43ba60f74c --ver 10 --tag '#PWD_INSTAGRAM_BROWSER'
```

### Command Line Options

- `--password` or `-p`: The password to encrypt (required)
- `--ts` or `-t`: Custom timestamp (defaults to current Unix timestamp)
- `--key-id`: Key ID for encryption (default: 78)
- `--pub`: Public key in hex format (default: Instagram's public key)
- `--ver`: Encryption version (default: 10)
- `--tag`: Encryption tag (default: '#PWD_INSTAGRAM_BROWSER')

## How It Works

The encryption process follows Instagram's PolarisEnvelopeEncryption algorithm:

1. **Generate Random AES Key**: Creates a random 32-byte AES-256 key
2. **AES-GCM Encryption**: Encrypts the password using AES-256-GCM with:
   - IV: 12 zero bytes
   - AAD: Timestamp (UTF-8 encoded)
3. **Sealed Box Encryption**: Encrypts the AES key using Curve25519 sealed box with Instagram's public key
4. **Payload Assembly**: Combines all components into a specific binary format
5. **Final Format**: Outputs in Instagram's expected format: `#PWD_INSTAGRAM_BROWSER:version:timestamp:base64payload`

## Example Output

```
#PWD_INSTAGRAM_BROWSER:10:1757900872:AU5QANYERR3HgZZCCYVKy9vPDhzSsvdqyRgXvG6WCyTht6kdqWGpCAHG1v+Wca1HIsxajHQ7uhuxwVI7v8KWUhRC59gLuuSliyjHq5GW1UEvO61NCRNzbl0f7c46KgbGJYgHHHE4CjpcwXRT
```

## Files Description

- `encrypt_cli.js`: Main CLI application for password encryption
- `encryption.js`: Contains research notes and analysis of Instagram's encryption algorithm
- `cookies.txt`: Sample cookie file with Instagram CSRF token
- `resources.txt`: Documentation and analysis of the encryption process
- `package.json`: Node.js dependencies and project configuration

## Security Notes

⚠️ **Important Security Considerations:**

- This tool is for educational and research purposes only
- Never use this tool for unauthorized access to Instagram accounts
- The encryption keys and parameters may change over time
- Always respect Instagram's Terms of Service and applicable laws
- This implementation is based on reverse engineering and may not be 100% accurate

## Research Background

This tool was created through reverse engineering Instagram's web client encryption mechanism. The research involved:

- Analyzing network traffic during login attempts
- Examining JavaScript code in Instagram's web interface
- Understanding the PolarisEnvelopeEncryption algorithm
- Implementing the same cryptographic operations in Node.js

## Legal Disclaimer

This software is provided for educational and research purposes only. The authors are not responsible for any misuse of this tool. Users must comply with all applicable laws and Instagram's Terms of Service. Unauthorized access to computer systems is illegal and unethical.

## Contributing

This is a research project. If you find issues or have improvements, please feel free to submit issues or pull requests.

## License

This project is for educational purposes. Please use responsibly and in accordance with applicable laws and terms of service.
