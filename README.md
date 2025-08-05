# AES Hook Frida Script

این اسکریپت فریدا برای هوک کردن توابع AES در کتابخانه libgojni و استخراج کلید و IV طراحی شده است.

## Features

- هوک کردن توابع رمزنگاری و رمزگشایی AES
- استخراج کلیدها و IV ها
- ثبت فراخوانی توابع با پارامترها
- پشتیبانی از حالت‌های مختلف AES (ECB, CBC, GCM, etc.)
- قابلیت dump کردن حافظه
- مدیریت داده‌های استخراج شده

## Requirements

- Python 3.6+
- Frida
- Android device (rooted) or emulator
- ADB access

## Installation

```bash
# Install Frida
pip install frida-tools

# Install Frida on Android device
# Download frida-server from https://github.com/frida/frida/releases
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

## Usage

### 1. Basic Usage

```bash
# Attach to a running process
python3 aes_hook_runner.py -n com.example.app

# Spawn a new process
python3 aes_hook_runner.py -p com.example.app

# Use specific device
python3 aes_hook_runner.py -d <device_id> -p com.example.app
```

### 2. Interactive Mode

```bash
python3 aes_hook_runner.py -p com.example.app -m interactive
```

Commands available in interactive mode:
- `export` - Export current data
- `save [filename]` - Save data to file
- `quit` - Exit

### 3. Automated Mode

```bash
# Run for 5 minutes, export every 30 seconds
python3 aes_hook_runner.py -p com.example.app -m automated -t 300 -i 30
```

### 4. Using Frida CLI directly

```bash
# Load script into Frida
frida -U -f com.example.app -l aes_hook_frida.js --no-pause

# Attach to running process
frida -U -n com.example.app -l aes_hook_frida.js
```

## Script Details

### Hooked Functions

#### Encryption Functions:
- `AES_encrypt`
- `AES_ecb_encrypt`
- `AES_cbc_encrypt`
- `AES_cfb_encrypt`
- `AES_ofb_encrypt`
- `AES_ctr_encrypt`
- `AES_gcm_encrypt`
- `EVP_EncryptInit_ex`
- `EVP_EncryptUpdate`
- `EVP_EncryptFinal_ex`

#### Decryption Functions:
- `AES_decrypt`
- `AES_ecb_decrypt`
- `AES_cbc_decrypt`
- `AES_cfb_decrypt`
- `AES_ofb_decrypt`
- `AES_ctr_decrypt`
- `AES_gcm_decrypt`
- `EVP_DecryptInit_ex`
- `EVP_DecryptUpdate`
- `EVP_DecryptFinal_ex`

#### Key Generation Functions:
- `AES_set_encrypt_key`
- `AES_set_decrypt_key`
- `EVP_BytesToKey`
- `PKCS5_PBKDF2_HMAC`

### Extracted Data

The script extracts and logs:
- **Keys**: در فرمت hex و base64
- **IVs**: در فرمت hex و base64
- **Data**: پیش‌نمایش داده‌های رمزنگاری شده
- **Function calls**: اطلاعات فراخوانی توابع
- **Timestamps**: زمان فراخوانی
- **Thread IDs**: شناسه thread
- **Memory addresses**: آدرس‌های حافظه

### Output Format

```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "total_calls": 10,
  "unique_keys": 3,
  "unique_ivs": 5,
  "function_calls": [
    {
      "timestamp": "2024-01-01T12:00:00.000Z",
      "function": "AES_cbc_encrypt",
      "key": "0123456789abcdef...",
      "key_base64": "ASNFZ4mrze8=",
      "iv": "fedcba9876543210...",
      "iv_base64": "/ty6mHZUMhA=",
      "data_length": 64,
      "data_preview": "0123456789abcdef...",
      "address": "0x7f1234567890",
      "thread_id": 12345
    }
  ],
  "unique_keys_hex": ["key1_hex", "key2_hex", "key3_hex"],
  "unique_keys_base64": ["key1_b64", "key2_b64", "key3_b64"],
  "unique_ivs_hex": ["iv1_hex", "iv2_hex", "iv3_hex", "iv4_hex", "iv5_hex"],
  "unique_ivs_base64": ["iv1_b64", "iv2_b64", "iv3_b64", "iv4_b64", "iv5_b64"]
}
```

## Advanced Usage

### Custom Function Hooks

You can modify the script to hook additional functions:

```javascript
// Add custom function to hook
const customFunctions = [
    "your_custom_aes_function",
    "another_crypto_function"
];

customFunctions.forEach(funcName => {
    const funcAddr = Module.findExportByName("libgojni.so", funcName);
    if (funcAddr) {
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                // Your custom hook logic
            }
        });
    }
});
```

### Memory Dump

```javascript
// Dump memory region
function dumpMemory(address, size) {
    try {
        return Memory.readByteArray(ptr(address), size);
    } catch (e) {
        console.log("[-] Failed to dump memory: " + e.message);
        return null;
    }
}
```

### Real-time Monitoring

```bash
# Monitor in real-time with custom interval
python3 aes_hook_runner.py -p com.example.app -m automated -t 3600 -i 5
```

## Troubleshooting

### Common Issues

1. **Process not found**
   ```bash
   # Check if process is running
   adb shell ps | grep com.example.app
   
   # List all processes
   frida-ps -U
   ```

2. **Permission denied**
   ```bash
   # Ensure device is rooted
   adb shell su
   
   # Check Frida server is running
   adb shell ps | grep frida-server
   ```

3. **Script not loading**
   ```bash
   # Check script syntax
   node -c aes_hook_frida.js
   
   # Test with simple script first
   frida -U -f com.example.app -e "console.log('Test')"
   ```

### Debug Mode

```bash
# Enable verbose logging
frida -U -f com.example.app -l aes_hook_frida.js --runtime=v8 --enable-jit
```

## Security Considerations

⚠️ **Warning**: This script is for educational and security research purposes only.

- Only use on applications you own or have permission to test
- Be aware of legal implications in your jurisdiction
- Do not use for malicious purposes
- Respect privacy and data protection laws

## Contributing

Feel free to contribute improvements:
- Add support for more crypto libraries
- Improve error handling
- Add more export formats
- Enhance memory analysis capabilities

## License

This project is for educational purposes. Use responsibly and in accordance with applicable laws.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review Frida documentation
3. Check Android debugging guides
4. Ensure proper permissions and setup