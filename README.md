# AES Hook Frida Script for libgojni

این اسکریپت فریدا برای هوک کردن توابع AES در کتابخانه libgojni و استخراج کلید و IV طراحی شده است.

## ویژگی‌ها

- هوک کردن توابع OpenSSL AES (`AES_encrypt`, `AES_decrypt`, `AES_set_encrypt_key`, `AES_set_decrypt_key`)
- هوک کردن توابع EVP (`EVP_EncryptInit_ex`, `EVP_DecryptInit_ex`, `EVP_EncryptUpdate`)
- هوک کردن توابع سفارشی در libgojni
- هوک کردن تابع `malloc` برای تشخیص تخصیص حافظه کلید/IV
- استخراج خودکار کلیدها و IV ها
- نمایش داده‌ها در فرمت‌های مختلف (Hex, Base64, UTF-8)
- گزارش‌گیری خودکار هر 30 ثانیه

## پیش‌نیازها

1. **Frida** نصب شده باشد
2. **ADB** برای اتصال به دستگاه Android
3. دستگاه Android root شده یا قابل debug

## نصب Frida

```bash
# نصب Frida CLI
pip install frida-tools

# نصب Frida server روی دستگاه Android
# دانلود از: https://github.com/frida/frida/releases
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

## نحوه استفاده

### 1. اجرای اپلیکیشن جدید

```bash
# برای اجرای اپلیکیشن جدید
frida -U -f com.target.app -l aes_hook_frida.js --no-pause
```

### 2. اتصال به اپلیکیشن در حال اجرا

```bash
# برای اتصال به اپلیکیشن در حال اجرا
frida -U -n "App Name" -l aes_hook_frida.js --no-pause
```

### 3. اتصال به پروسه با PID

```bash
# برای اتصال به پروسه با PID مشخص
frida -U -p <PID> -l aes_hook_frida.js --no-pause
```

## خروجی اسکریپت

اسکریپت اطلاعات زیر را استخراج و نمایش می‌دهد:

### کلیدهای استخراج شده
- فرمت Hex
- فرمت Base64
- اندازه کلید
- منبع استخراج
- زمان استخراج

### IV های استخراج شده
- فرمت Hex
- فرمت Base64
- اندازه IV
- منبع استخراج
- زمان استخراج

### داده‌های رمزنگاری شده
- داده‌های ورودی و خروجی
- فرمت‌های مختلف نمایش

## توابع قابل استفاده

### در زمان اجرا
```javascript
// نمایش خلاصه داده‌های استخراج شده
extractSummary()

// دریافت کلیدهای استخراج شده
getExtractedKeys()

// دریافت IV های استخراج شده
getExtractedIVs()

// دریافت داده‌های رمزنگاری شده
getEncryptedData()
```

## مثال خروجی

```
[+] AES Hook Script Loaded
[+] Starting to hook AES functions in libgojni...
[+] Starting AES hooking...
[+] Hooking OpenSSL AES functions...
[+] AES_set_encrypt_key hooked successfully
[+] AES_set_decrypt_key hooked successfully
[+] Hooking EVP AES functions...
[+] EVP_EncryptInit_ex hooked successfully
[+] EVP_DecryptInit_ex hooked successfully
[+] EVP_EncryptUpdate hooked successfully
[+] Hooking libgojni functions...
[+] Found libgojni module: libgojni.so at 0x7f8b4c0000
[+] Hooking memory allocation functions...
[+] malloc hooked successfully
[+] All hooks installed successfully

[+] AES_set_encrypt_key called
[-] User key: 0x7f8b4c1234
[-] Bits: 256
[-] Key schedule: 0x7f8b4c5678
[-] Extracted Key:
    Hex: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    Base64: ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=
    Size: 32 bytes

============================================================
EXTRACTION SUMMARY
============================================================

Extracted Keys (1):
Key 1:
  Hex: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  Base64: ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=
  Size: 32 bytes
  Source: AES_set_encrypt_key
  Timestamp: 2024-01-15T10:30:45.123Z
```

## نکات مهم

1. **امنیت**: این اسکریپت فقط برای اهداف آموزشی و تست امنیت استفاده شود
2. **قانونی**: قبل از استفاده، اطمینان حاصل کنید که مجاز به تست اپلیکیشن مورد نظر هستید
3. **عملکرد**: اسکریپت ممکن است کمی روی عملکرد اپلیکیشن تأثیر بگذارد
4. **خطاها**: برخی توابع ممکن است در اپلیکیشن مورد نظر موجود نباشند

## عیب‌یابی

### مشکل: اپلیکیشن crash می‌کند
- بررسی کنید که Frida server در حال اجرا است
- اطمینان حاصل کنید که دستگاه root شده است
- بررسی کنید که اپلیکیشن قابل debug است

### مشکل: هیچ تابعی hook نمی‌شود
- بررسی کنید که libgojni در اپلیکیشن استفاده می‌شود
- ممکن است اپلیکیشن از کتابخانه‌های دیگری استفاده کند
- بررسی کنید که توابع مورد نظر در کتابخانه موجود هستند

### مشکل: داده‌ها استخراج نمی‌شوند
- ممکن است کلیدها در زمان‌های مختلف تولید شوند
- بررسی کنید که اپلیکیشن عملیات رمزنگاری انجام می‌دهد
- از تابع `extractSummary()` برای بررسی داده‌های استخراج شده استفاده کنید

## سفارشی‌سازی

برای اضافه کردن توابع جدید یا تغییر رفتار اسکریپت:

1. تابع جدید را در بخش مربوطه اضافه کنید
2. از `Interceptor.attach()` برای hook کردن استفاده کنید
3. از توابع `bytesToHex()` و `bytesToBase64()` برای تبدیل داده‌ها استفاده کنید
4. داده‌های استخراج شده را در آرایه‌های مربوطه ذخیره کنید

## پشتیبانی

برای گزارش مشکلات یا پیشنهادات، لطفاً issue ایجاد کنید.