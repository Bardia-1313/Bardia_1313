# راهنمای استفاده از اسکریپت‌های فریدا برای هوک AES در libgojni

## فایل‌های موجود

1. **frida_aes_hook.js** - اسکریپت پایه برای هوک توابع AES
2. **frida_aes_advanced.js** - اسکریپت پیشرفته با قابلیت‌های اضافی

## نحوه استفاده

### روش 1: اتصال به پروسه در حال اجرا
```bash
# پیدا کردن PID برنامه
adb shell ps | grep [package_name]

# اجرای اسکریپت پایه
frida -U -p [PID] -l frida_aes_hook.js

# اجرای اسکریپت پیشرفته
frida -U -p [PID] -l frida_aes_advanced.js
```

### روش 2: اجرای همزمان با برنامه
```bash
# اجرای برنامه و اتصال اسکریپت
frida -U -f [package_name] -l frida_aes_hook.js --no-pause

# اجرای اسکریپت پیشرفته
frida -U -f [package_name] -l frida_aes_advanced.js --no-pause
```

### روش 3: اجرای از طریق frida-server
```bash
# روی دستگاه Android
./frida-server &

# روی کامپیوتر
frida -H [DEVICE_IP]:27042 -f [package_name] -l frida_aes_hook.js
```

## دستورات تعاملی

بعد از اجرای اسکریپت پیشرفته، می‌توانید از دستورات زیر استفاده کنید:

```javascript
// نمایش کلیدهای ذخیره شده
printKeys()

// نمایش تعداد توابع هوک شده
hookedCount()
```

## قابلیت‌های اسکریپت پایه

- هوک توابع AES استاندارد OpenSSL
- هوک توابع EVP برای رمزنگاری
- هوک توابع Go crypto
- نمایش کلیدها و داده‌های رمزگذاری
- ردیابی تخصیص حافظه

## قابلیت‌های اسکریپت پیشرفته

- نمایش بهتر داده‌ها (HEX + ASCII)
- ذخیره و ردیابی کلیدها
- ردیابی stack trace
- گزارش‌دهی دوره‌ای
- پشتیبانی از timeout
- هوک memcpy برای تشخیص کپی کلید

## توابع قابل هوک

### توابع OpenSSL AES:
- `AES_set_encrypt_key`
- `AES_set_decrypt_key`
- `AES_encrypt`
- `AES_decrypt`
- `AES_cbc_encrypt`

### توابع EVP:
- `EVP_EncryptInit_ex`
- `EVP_DecryptInit_ex`
- `EVP_EncryptUpdate`
- `EVP_DecryptUpdate`

### توابع Go Crypto:
- `crypto/aes.NewCipher`
- `crypto/cipher.NewCBCEncrypter`
- `crypto/cipher.NewGCM`

## خروجی نمونه

```
[*] Starting AES Hook Script for libgojni
[+] Found libgojni.so at: 0x7b8c000000
[+] Found AES_set_encrypt_key at: 0x7b8c123456
[+] Successfully hooked: AES_set_encrypt_key

🔐 [OPENSSL] AES_set_encrypt_key called
Thread: 12345
Timestamp: 2024-01-15T10:30:00.000Z

╔══ AES Key (128 bits) ══╗
║ Address: 0x7b8c234567
║ Size: 16 bytes
║ HEX:
║ 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
║ ASCII: +~..(......O<
╚══════════════════════════╝

[KEY] Saved key: 2b7e151628aed2a6abf7158809cf4f3c... (length: 16)
```

## نکات مهم

1. **دسترسی Root**: برای اجرای فریدا بر روی Android نیاز به root دارید
2. **SELinux**: ممکن است نیاز به غیرفعال کردن SELinux باشد
3. **کتابخانه**: مطمئن شوید libgojni.so در برنامه موجود است
4. **Performance**: اسکریپت پیشرفته ممکن است برنامه را کندتر کند

## عیب‌یابی

### اگر کتابخانه پیدا نشد:
```bash
# بررسی کتابخانه‌های موجود
frida -U -p [PID] -e "Process.enumerateModules().forEach(m => console.log(m.name))"
```

### اگر توابع پیدا نشدند:
```bash
# بررسی توابع صادر شده
frida -U -p [PID] -e "Module.enumerateExports('libgojni.so').forEach(e => console.log(e.name))"
```

### برای دیباگ بیشتر:
اسکریپت را با گزینه verbose اجرا کنید:
```bash
frida -U -p [PID] -l frida_aes_advanced.js --runtime=v8 --debug
```