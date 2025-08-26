
# TamimHardcode 🔐

A secure encryption/decryption Node.js package with built-in license protection and machine binding.

## Features

- 🔒 **Military-grade encryption** using AES-256-GCM
- 🏷️ **License protection** - requires proper npm installation
- 💻 **Machine binding** - encrypted data is tied to the machine
- 📁 **File encryption/decryption** support
- 🛡️ **Anti-tampering** protection
- 🔑 **Custom password** support

## Installation

```bash
npm install tamimhardcode
```

## Usage

### Basic Encryption/Decryption

```javascript
const { encrypt, decrypt } = require('tamimhardcode');

// Encrypt text
const encrypted = encrypt("Your secret message");
console.log(encrypted); // Base64 encoded encrypted data

// Decrypt text
const decrypted = decrypt(encrypted);
console.log(decrypted); // "Your secret message"
```

### Using Custom Password

```javascript
const { encrypt, decrypt } = require('tamimhardcode');

const password = "mySecretPassword123!";
const encrypted = encrypt("Secret data", password);
const decrypted = decrypt(encrypted, password);
```

### Class-based Usage

```javascript
const { TamimHardcode } = require('tamimhardcode');

const tamim = new TamimHardcode();
const encrypted = tamim.encrypt("My secret");
const decrypted = tamim.decrypt(encrypted);
```

### File Encryption/Decryption

```javascript
const { encryptFile, decryptFile } = require('tamimhardcode');

// Encrypt a file
encryptFile('secret.txt', 'secret.txt.tamim');

// Decrypt a file
decryptFile('secret.txt.tamim', 'decrypted.txt');
```

### License Verification

```javascript
const { isLicensed, getInfo } = require('tamimhardcode');

console.log('Licensed:', isLicensed());
console.log('Package Info:', getInfo());
```

## Security Features

1. **Installation Verification**: The package checks if it's properly installed via npm
2. **Machine Binding**: Encrypted data can only be decrypted on the same machine
3. **License Protection**: Built-in license verification system
4. **Secure Key Derivation**: Uses PBKDF2 with 100,000 iterations
5. **Authentication**: Uses GCM mode for authenticated encryption

## Error Handling

The package throws descriptive errors for:
- Invalid installation
- License verification failure
- Machine verification failure
- Decryption errors
- File operation errors

## Testing

```bash
npm test
```

## Demo

```bash
npm run demo
```

## License

This package is proprietary software. Unauthorized use, distribution, or modification is prohibited.

## Author

Created by Tamim

---

⚠️ **Important**: This package requires proper installation via npm to function. Direct file copying will not work due to built-in protection mechanisms.
