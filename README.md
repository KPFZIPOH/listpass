
# Disclaimer
The author is not responsible for any misuse of this software. Use it at your own risk and ensure compliance with all applicable laws and regulations.

# Ethical Considerations
Use Responsibly: This software is for educational and testing purposes only. Using a keylogger to monitor someone without their explicit consent is illegal in many jurisdictions and violates privacy rights.

Transparency: Always inform and obtain consent from users before deploying this software on their systems.

Security: The ZIP file is encrypted, but ensure the password and output files are handled securely to prevent unauthorized access.

# listpass
This app would list out all the current logged on user's chrome website passwords if the user clicked save the website password when using chrome. 

# Chrome Password Extractor

**Author**: KPFZIPOH
**Last Updated**: June 06, 2025

## Description

Chrome Password Extractor is a Python tool designed to retrieve and decrypt saved login credentials from Google Chrome's password database across multiple user profiles. It supports both older DPAPI-encrypted passwords and newer AES-GCM encrypted passwords, with robust error handling, logging, and clean output formatting.

**Note**: This tool is intended for educational and ethical purposes only, such as security research or password recovery on your own system. Unauthorized access to or extraction of passwords is illegal and unethical. Use responsibly and ensure compliance with all applicable laws.

## Features

- Extracts passwords from all Chrome profiles (Default, Profile 1, Profile 2, etc.).
- Supports both DPAPI and AES-GCM decryption methods.
- Comprehensive logging to track operations and errors.
- Robust error handling to prevent crashes.
- Clean, formatted console output for easy reading.
- Cross-platform path handling using `pathlib`.
- Safe temporary file management for database operations.

## Requirements

- **Operating System**: Windows (due to DPAPI dependency).
- **Python Version**: Python 3.6 or higher.
- **Dependencies**:
  - `pywin32` (for Windows DPAPI decryption)
  - `pycryptodome` (for AES-GCM decryption)
- **Google Chrome**: Installed with saved passwords in the user data directory.

## Installation

1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/your-username/chrome-password-extractor.git
   cd chrome-password-extractor
