# راهنمای استفاده از اسکریپت‌های فریدا برای هوک AES

## Frida AES Hooking Scripts Usage Guide

### فایل‌های ایجاد شده / Created Files:

1. **frida_aes_hook.js** - اسکریپت جامع برای هوک توابع AES استاندارد
   - General AES hooking script for standard AES functions

2. **frida_go_aes_hook.js** - اسکریپت تخصصی برای توابع AES در Go
   - Specialized script for Go crypto functions

---

## نحوه استفاده / Usage Instructions:

### پیش‌نیازها / Prerequisites:
```bash
# نصب فریدا / Install Frida
pip install frida-tools

# بررسی نصب / Verify installation  
frida --version
```

### اجرای اسکریپت‌ها / Running the Scripts:

#### 1. هوک اپلیکیشن اندروید / Hook Android Application:
```bash
# اتصال به دستگاه و اجرای اسکریپت عمومی
frida -U -f com.example.app -l frida_aes_hook.js --no-pause

# اجرای اسکریپت Go-specific
frida -U -f com.example.app -l frida_go_aes_hook.js --no-pause

# اتصال به پروسه در حال اجرا
frida -U com.example.app -l frida_aes_hook.js
```

#### 2. هوک اپلیکیشن دسکتاپ / Hook Desktop Application:
```bash
# اجرای روی پروسه مشخص
frida -p <PID> -l frida_aes_hook.js

# اجرای با نام پروسه
frida -n "process_name" -l frida_go_aes_hook.js
```

#### 3. استفاده همزمان از هر دو اسکریپت / Use Both Scripts:
```bash
frida -U -f com.example.app -l frida_aes_hook.js -l frida_go_aes_hook.js --no-pause
```

---

## خروجی مورد انتظار / Expected Output:

### کلیدهای AES / AES Keys:
```
[AES_KEY] Size: 32 bytes
[AES_KEY] Data: 2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe
[AES_KEY] Address: 0x7f8b2c001000
```

### بردار اولیه / Initialization Vector:
```
[CIPHER_IV] Size: 16 bytes  
[CIPHER_IV] Data: 000102030405060708090a0b0c0d0e0f
[CIPHER_IV] Address: 0x7f8b2c001020
```

### متن رمزگذاری شده / Encrypted Data:
```
[CRYPT_SRC] Slice - Len: 32, Cap: 32, Ptr: 0x7f8b2c001040
[CRYPT_SRC] Data: 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51
```

---

## توابع هوک شده / Hooked Functions:

### توابع استاندارد AES / Standard AES Functions:
- `AES_encrypt` / `AES_decrypt`
- `AES_set_encrypt_key` / `AES_set_decrypt_key`  
- `AES_cbc_encrypt` / `AES_cfb128_encrypt` / `AES_ofb128_encrypt`
- `EVP_EncryptInit_ex` / `EVP_DecryptInit_ex`

### توابع Go Crypto / Go Crypto Functions:
- `crypto/aes.NewCipher`
- `crypto/cipher.NewCBCEncrypter` / `NewCBCDecrypter`
- `crypto/cipher.(*cbc).CryptBlocks`
- `crypto/cipher.NewGCM` / `(*gcm).Seal` / `(*gcm).Open`

---

## نکات مهم / Important Notes:

### تنظیمات اضافی / Additional Settings:
```javascript
// برای افزایش جزئیات خروجی
console.log = function(msg) { 
    send(msg); 
    // Save to file if needed
};

// فیلتر کردن خروجی بر اساس سایز کلید
if (keySize >= 16 && keySize <= 32) {
    // Process only valid AES key sizes
}
```

### عیب‌یابی / Troubleshooting:

#### اگر کتابخانه پیدا نشد / If Library Not Found:
```bash
# لیست کردن تمام ماژول‌ها
frida -U -f com.example.app --no-pause -q -e "Process.enumerateModules().forEach(m => console.log(m.name))"

# جستجو برای کتابخانه‌های مشکوک
frida -U -f com.example.app --no-pause -q -e "Process.enumerateModules().filter(m => m.name.includes('go') || m.name.includes('crypto')).forEach(m => console.log(m.name + ' - ' + m.base))"
```

#### اگر توابع هوک نشدند / If Functions Not Hooked:
1. بررسی کنید که نام کتابخانه صحیح است
2. ممکن است توابع stripped شده باشند
3. از Symbol scanning استفاده کنید
4. Memory hooking را امتحان کنید

---

## مثال‌های پیشرفته / Advanced Examples:

### ذخیره خروجی در فایل / Save Output to File:
```bash
frida -U -f com.example.app -l frida_aes_hook.js --no-pause > aes_keys.log 2>&1
```

### فیلتر کردن فقط کلیدها / Filter Only Keys:
```bash
frida -U -f com.example.app -l frida_aes_hook.js --no-pause | grep -E "(AES_KEY|CIPHER_IV)"
```

### استفاده از فریدا در حالت Spawn / Using Frida in Spawn Mode:
```bash
# شروع اپلیکیشن و توقف قبل از main
frida -U -f com.example.app -l frida_aes_hook.js

# در کنسول فریدا:
%resume  # برای ادامه اجرا
```

---

## امنیت / Security Notes:

⚠️ **هشدار امنیتی / Security Warning:**
- این ابزارها فقط برای تست امنیت و تحلیل مجاز استفاده شوند
- Use these tools only for authorized security testing and analysis
- احترام به قوانین محلی و بین‌المللی ضروری است
- Respect local and international laws

---

## پشتیبانی / Support:

برای مشکلات یا سوالات / For issues or questions:
1. بررسی کنید که فریدا به درستی نصب شده است
2. مطمئن شوید که دستگاه/اپلیکیشن قابل دسترسی است  
3. لاگ‌های خطا را بررسی کنید
4. نسخه‌های مختلف اسکریپت را امتحان کنید