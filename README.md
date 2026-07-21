# AES Hook Frida Script for libgojni

این اسکریپت فریدا برای هوک کردن توابع AES در کتابخانه libgojni و استخراج کلید و IV طراحی شده است.

## Features

- **هوک توابع رمزنگاری AES**: شامل `AES_encrypt`, `AES_decrypt`, `AES_cbc_encrypt`, `AES_cbc_decrypt`
- **هوک توابع GCM**: شامل `AES_gcm_encrypt`, `AES_gcm_decrypt`
- **هوک توابع کلید**: شامل `AES_set_encrypt_key`, `AES_set_decrypt_key`
- **هوک توابع EVP**: شامل `EVP_aes_256_cbc`, `EVP_aes_128_cbc`
- **هوک توابع JNI**: برای توابع سفارشی که ممکن است از AES استفاده کنند
- **اسکن حافظه**: جستجوی خودکار کلیدهای AES در حافظه
- **لاگ کامل**: ثبت تمام فراخوانی‌ها با timestamp
- **استخراج کلید و IV**: ذخیره کلیدها و IV های منحصر به فرد

## Prerequisites

- Frida installed on your system
- Root access on the target device (for Android)
- Target application that uses libgojni library

## Installation

1. Install Frida:
```bash
pip install frida-tools
```

2. Download the script:
```bash
wget https://raw.githubusercontent.com/your-repo/aes_hook_frida.js
```

## Usage

### Basic Usage

```bash
# Attach to running process
frida -U -l aes_hook_frida.js -f com.example.targetapp

# Or attach to specific PID
frida -U -l aes_hook_frida.js -p <PID>
```

### Advanced Usage

```bash
# Spawn and attach to app
frida -U -l aes_hook_frida.js --no-pause -f com.example.targetapp

# With custom parameters
frida -U -l aes_hook_frida.js -f com.example.targetapp --runtime=v8
```

### Using Frida CLI

```javascript
// Load the script
%load aes_hook_frida.js

// Access extracted data
global.aesHook.getExtractedKeys()
global.aesHook.getExtractedIVs()
global.aesHook.getHookCount()

// Manually scan for keys
global.aesHook.scanForKeys()
```

## Output Format

The script provides detailed logging with the following format:

```
[2024-01-15T10:30:45.123Z] [1] AES_encrypt called
[2024-01-15T10:30:45.124Z] [KEY] AES Key: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
[2024-01-15T10:30:45.125Z] [DATA] Plaintext: 48 65 6c 6c 6f 20 57 6f 72 6c 64 21 00 00 00 00
[2024-01-15T10:30:45.126Z] [DATA] Ciphertext: a1 b2 c3 d4 e5 f6 07 08 09 0a 0b 0c 0d 0e 0f 10
[2024-01-15T10:30:45.127Z] [1] AES_encrypt returned: 0x0
```

## Hooked Functions

### Core AES Functions
- `AES_encrypt` - Single block encryption
- `AES_decrypt` - Single block decryption
- `AES_cbc_encrypt` - CBC mode encryption/decryption
- `AES_cbc_decrypt` - CBC mode decryption
- `AES_gcm_encrypt` - GCM mode encryption
- `AES_gcm_decrypt` - GCM mode decryption

### Key Management Functions
- `AES_set_encrypt_key` - Set encryption key
- `AES_set_decrypt_key` - Set decryption key

### EVP Wrapper Functions
- `EVP_aes_256_cbc` - OpenSSL EVP AES-256-CBC
- `EVP_aes_128_cbc` - OpenSSL EVP AES-128-CBC

### JNI Functions
- `Java_com_example_encrypt`
- `Java_com_example_decrypt`
- `Java_com_example_AES`
- `Java_com_example_crypto`

## Configuration

You can modify the script to add more functions or change behavior:

```javascript
// Add custom JNI function names
const jniFunctions = [
    "Java_com_example_encrypt",
    "Java_com_example_decrypt",
    "Java_com_example_AES",
    "Java_com_example_crypto",
    "Java_your_custom_function"  // Add your custom function
];

// Change memory scan size
const data = Memory.readByteArray(range.base, Math.min(range.size, 2048 * 1024)); // 2MB instead of 1MB
```

## Troubleshooting

### Common Issues

1. **libgojni not found**:
   ```
   [!] libgojni not found, trying to hook anyway...
   ```
   - Check if the library is loaded
   - Verify the library name
   - Try hooking other crypto libraries

2. **No hooks triggered**:
   - Ensure the app actually uses AES encryption
   - Check if functions are exported from the library
   - Try different function names

3. **Memory read errors**:
   - Normal for invalid memory addresses
   - Script handles these gracefully

### Debug Mode

Enable debug logging by modifying the script:

```javascript
const DEBUG = true;

function logWithTimestamp(message) {
    const now = new Date();
    if (DEBUG) {
        console.log(`[DEBUG][${now.toISOString()}] ${message}`);
    }
    console.log(`[${now.toISOString()}] ${message}`);
}
```

## Security Considerations

⚠️ **Warning**: This script is for educational and security research purposes only.

- Only use on applications you own or have permission to test
- Be aware of legal implications in your jurisdiction
- Do not use for malicious purposes

## Examples

### Example 1: Basic Hook
```bash
frida -U -l aes_hook_frida.js -f com.example.encryptionapp
```

### Example 2: Attach to Running Process
```bash
# Find process
adb shell ps | grep targetapp

# Attach with Frida
frida -U -l aes_hook_frida.js -p 12345
```

### Example 3: Custom Function Hook
```javascript
// Add to the script
const customFunc = Module.findExportByName("libgojni.so", "custom_encrypt_function");
if (customFunc) {
    Interceptor.attach(customFunc, {
        onEnter: function(args) {
            console.log("Custom function called!");
            // Your custom logic here
        }
    });
}
```

## Contributing

Feel free to contribute by:
- Adding support for more crypto libraries
- Improving memory scanning algorithms
- Adding support for other encryption algorithms
- Enhancing error handling

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check the troubleshooting section
- Review Frida documentation

---

**Note**: This script is designed for Android applications using the libgojni library. For other platforms or libraries, modifications may be required.