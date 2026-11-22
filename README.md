# Secure File Encryption and Decryption System

A local Flask web application mini project for Information Network and Security. It encrypts uploaded files with AES-256-GCM and derives keys from passwords using scrypt.

## Requirements
- Python 3.10 or newer
- VS Code (recommended)
- Internet connection only for the first installation of Python packages

## Setup on Windows (PowerShell)
1. Extract this ZIP file.
2. Open the extracted `Secure_File_Encryption_Project` folder in VS Code.
3. Open Terminal > New Terminal.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```

5. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, run this for the current terminal only, then activate again:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\.venv\Scripts\Activate.ps1
   ```

6. Install dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

7. Start the application:

   ```powershell
   py app.py
   ```

8. Open `http://127.0.0.1:5000` in your browser.

## How to test manually
1. Create a small text file named `sample.txt` containing `Hello, security!`.
2. In Encrypt a file, select it and enter a password of at least 8 characters.
3. Download the `.sfe` file.
4. In Decrypt a file, select that `.sfe` file and enter the same password.
5. Open the recovered file and confirm its content matches the original.
6. Try a wrong password; decryption should be rejected.

## Run automated tests
Install pytest, then run:

```powershell
py -m pip install pytest
py -m pytest -q
```

## Security notes and limitations
- AES-GCM provides confidentiality and authentication/integrity.
- A fresh 16-byte salt and 12-byte nonce are generated for each encryption.
- Scrypt derives a 32-byte (256-bit) key from the password.
- Passwords are not saved. If the password is lost, the file cannot be recovered.
- This educational version processes files in memory and limits uploads to 25 MB.
- Temporary output files are written under `instance/uploads`; remove this folder after testing.
- Run only on localhost for the college demonstration. Do not expose the development server to the public internet. A real deployment requires HTTPS, a production WSGI server, CSRF protection, access controls, secure temporary-file cleanup, and operational security review.
