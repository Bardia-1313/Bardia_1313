/*
 * Frida Script for Hooking AES Functions in libgojni
 * این اسکریپت برای هوک کردن توابع AES در کتابخانه libgojni و استخراج کلید و IV طراحی شده است
 * 
 * Usage:
 * frida -U -f com.target.app -l aes_hook_frida.js --no-pause
 * 
 * یا برای اتصال به پروسه در حال اجرا:
 * frida -U -n "App Name" -l aes_hook_frida.js --no-pause
 */

console.log("[+] AES Hook Script Loaded");
console.log("[+] Starting to hook AES functions in libgojni...");

// Global variables to store extracted data
var extractedKeys = [];
var extractedIVs = [];
var encryptedData = [];

// Utility function to convert bytes to hex string
function bytesToHex(bytes) {
    if (!bytes) return "null";
    return Array.from(bytes, byte => ('0' + (byte & 0xFF).toString(16)).slice(-2)).join('');
}

// Utility function to convert bytes to base64
function bytesToBase64(bytes) {
    if (!bytes) return "null";
    return btoa(String.fromCharCode.apply(null, bytes));
}

// Utility function to print buffer contents
function printBuffer(buffer, size, label) {
    if (!buffer) {
        console.log(`[${label}] Buffer is null`);
        return;
    }
    
    try {
        const bytes = Memory.readByteArray(buffer, size);
        console.log(`[${label}] Hex: ${bytesToHex(bytes)}`);
        console.log(`[${label}] Base64: ${bytesToBase64(bytes)}`);
        console.log(`[${label}] Size: ${size} bytes`);
        
        // Try to decode as UTF-8 string
        try {
            const str = Memory.readUtf8String(buffer, size);
            if (str && str.length > 0 && str.length < 1000) {
                console.log(`[${label}] UTF-8: ${str}`);
            }
        } catch (e) {
            // Ignore UTF-8 decode errors
        }
    } catch (e) {
        console.log(`[${label}] Error reading buffer: ${e.message}`);
    }
}

// Hook OpenSSL AES functions
function hookOpenSSLAES() {
    console.log("[+] Hooking OpenSSL AES functions...");
    
    // Hook AES_encrypt
    try {
        const aes_encrypt = Module.findExportByName("libcrypto.so", "AES_encrypt");
        if (aes_encrypt) {
            Interceptor.attach(aes_encrypt, {
                onEnter: function(args) {
                    console.log("\n[+] AES_encrypt called");
                    console.log("[-] Input buffer:", args[0]);
                    console.log("[-] Output buffer:", args[1]);
                    console.log("[-] Key schedule:", args[2]);
                    
                    // Extract key from key schedule (simplified)
                    try {
                        const keyData = Memory.readByteArray(args[2], 176); // AES key schedule size
                        console.log("[-] Key schedule data:", bytesToHex(keyData));
                    } catch (e) {
                        console.log("[-] Error reading key schedule:", e.message);
                    }
                }
            });
            console.log("[+] AES_encrypt hooked successfully");
        }
    } catch (e) {
        console.log("[-] Error hooking AES_encrypt:", e.message);
    }
    
    // Hook AES_decrypt
    try {
        const aes_decrypt = Module.findExportByName("libcrypto.so", "AES_decrypt");
        if (aes_decrypt) {
            Interceptor.attach(aes_decrypt, {
                onEnter: function(args) {
                    console.log("\n[+] AES_decrypt called");
                    console.log("[-] Input buffer:", args[0]);
                    console.log("[-] Output buffer:", args[1]);
                    console.log("[-] Key schedule:", args[2]);
                }
            });
            console.log("[+] AES_decrypt hooked successfully");
        }
    } catch (e) {
        console.log("[-] Error hooking AES_decrypt:", e.message);
    }
    
    // Hook AES_set_encrypt_key
    try {
        const aes_set_encrypt_key = Module.findExportByName("libcrypto.so", "AES_set_encrypt_key");
        if (aes_set_encrypt_key) {
            Interceptor.attach(aes_set_encrypt_key, {
                onEnter: function(args) {
                    console.log("\n[+] AES_set_encrypt_key called");
                    console.log("[-] User key:", args[0]);
                    console.log("[-] Bits:", args[1]);
                    console.log("[-] Key schedule:", args[2]);
                    
                    // Extract the actual key
                    try {
                        const keySize = parseInt(args[1]) / 8;
                        const keyData = Memory.readByteArray(args[0], keySize);
                        const keyHex = bytesToHex(keyData);
                        const keyBase64 = bytesToBase64(keyData);
                        
                        console.log("[-] Extracted Key:");
                        console.log("    Hex:", keyHex);
                        console.log("    Base64:", keyBase64);
                        console.log("    Size:", keySize, "bytes");
                        
                        extractedKeys.push({
                            hex: keyHex,
                            base64: keyBase64,
                            size: keySize,
                            timestamp: new Date().toISOString()
                        });
                    } catch (e) {
                        console.log("[-] Error extracting key:", e.message);
                    }
                }
            });
            console.log("[+] AES_set_encrypt_key hooked successfully");
        }
    } catch (e) {
        console.log("[-] Error hooking AES_set_encrypt_key:", e.message);
    }
    
    // Hook AES_set_decrypt_key
    try {
        const aes_set_decrypt_key = Module.findExportByName("libcrypto.so", "AES_set_decrypt_key");
        if (aes_set_decrypt_key) {
            Interceptor.attach(aes_set_decrypt_key, {
                onEnter: function(args) {
                    console.log("\n[+] AES_set_decrypt_key called");
                    console.log("[-] User key:", args[0]);
                    console.log("[-] Bits:", args[1]);
                    console.log("[-] Key schedule:", args[2]);
                    
                    // Extract the actual key
                    try {
                        const keySize = parseInt(args[1]) / 8;
                        const keyData = Memory.readByteArray(args[0], keySize);
                        const keyHex = bytesToHex(keyData);
                        const keyBase64 = bytesToBase64(keyData);
                        
                        console.log("[-] Extracted Key:");
                        console.log("    Hex:", keyHex);
                        console.log("    Base64:", keyBase64);
                        console.log("    Size:", keySize, "bytes");
                        
                        extractedKeys.push({
                            hex: keyHex,
                            base64: keyBase64,
                            size: keySize,
                            timestamp: new Date().toISOString()
                        });
                    } catch (e) {
                        console.log("[-] Error extracting key:", e.message);
                    }
                }
            });
            console.log("[+] AES_set_decrypt_key hooked successfully");
        }
    } catch (e) {
        console.log("[-] Error hooking AES_set_decrypt_key:", e.message);
    }
}

// Hook EVP (Envelope) functions for AES
function hookEVPAES() {
    console.log("[+] Hooking EVP AES functions...");
    
    // Hook EVP_EncryptInit_ex
    try {
        const evp_encrypt_init_ex = Module.findExportByName("libcrypto.so", "EVP_EncryptInit_ex");
        if (evp_encrypt_init_ex) {
            Interceptor.attach(evp_encrypt_init_ex, {
                onEnter: function(args) {
                    console.log("\n[+] EVP_EncryptInit_ex called");
                    console.log("[-] Context:", args[0]);
                    console.log("[-] Cipher:", args[1]);
                    console.log("[-] Engine:", args[2]);
                    console.log("[-] Key:", args[3]);
                    console.log("[-] IV:", args[4]);
                    
                    // Extract key and IV
                    try {
                        if (args[3]) {
                            const keyData = Memory.readByteArray(args[3], 32); // Assuming 256-bit key
                            const keyHex = bytesToHex(keyData);
                            const keyBase64 = bytesToBase64(keyData);
                            
                            console.log("[-] Extracted Key:");
                            console.log("    Hex:", keyHex);
                            console.log("    Base64:", keyBase64);
                            
                            extractedKeys.push({
                                hex: keyHex,
                                base64: keyBase64,
                                size: 32,
                                timestamp: new Date().toISOString()
                            });
                        }
                        
                        if (args[4]) {
                            const ivData = Memory.readByteArray(args[4], 16); // AES block size
                            const ivHex = bytesToHex(ivData);
                            const ivBase64 = bytesToBase64(ivData);
                            
                            console.log("[-] Extracted IV:");
                            console.log("    Hex:", ivHex);
                            console.log("    Base64:", ivBase64);
                            
                            extractedIVs.push({
                                hex: ivHex,
                                base64: ivBase64,
                                size: 16,
                                timestamp: new Date().toISOString()
                            });
                        }
                    } catch (e) {
                        console.log("[-] Error extracting key/IV:", e.message);
                    }
                }
            });
            console.log("[+] EVP_EncryptInit_ex hooked successfully");
        }
    } catch (e) {
        console.log("[-] Error hooking EVP_EncryptInit_ex:", e.message);
    }
    
    // Hook EVP_DecryptInit_ex
    try {
        const evp_decrypt_init_ex = Module.findExportByName("libcrypto.so", "EVP_DecryptInit_ex");
        if (evp_decrypt_init_ex) {
            Interceptor.attach(evp_decrypt_init_ex, {
                onEnter: function(args) {
                    console.log("\n[+] EVP_DecryptInit_ex called");
                    console.log("[-] Context:", args[0]);
                    console.log("[-] Cipher:", args[1]);
                    console.log("[-] Engine:", args[2]);
                    console.log("[-] Key:", args[3]);
                    console.log("[-] IV:", args[4]);
                    
                    // Extract key and IV
                    try {
                        if (args[3]) {
                            const keyData = Memory.readByteArray(args[3], 32);
                            const keyHex = bytesToHex(keyData);
                            const keyBase64 = bytesToBase64(keyData);
                            
                            console.log("[-] Extracted Key:");
                            console.log("    Hex:", keyHex);
                            console.log("    Base64:", keyBase64);
                            
                            extractedKeys.push({
                                hex: keyHex,
                                base64: keyBase64,
                                size: 32,
                                timestamp: new Date().toISOString()
                            });
                        }
                        
                        if (args[4]) {
                            const ivData = Memory.readByteArray(args[4], 16);
                            const ivHex = bytesToHex(ivData);
                            const ivBase64 = bytesToBase64(ivData);
                            
                            console.log("[-] Extracted IV:");
                            console.log("    Hex:", ivHex);
                            console.log("    Base64:", ivBase64);
                            
                            extractedIVs.push({
                                hex: ivHex,
                                base64: ivBase64,
                                size: 16,
                                timestamp: new Date().toISOString()
                            });
                        }
                    } catch (e) {
                        console.log("[-] Error extracting key/IV:", e.message);
                    }
                }
            });
            console.log("[+] EVP_DecryptInit_ex hooked successfully");
        }
    } catch (e) {
        console.log("[-] Error hooking EVP_DecryptInit_ex:", e.message);
    }
    
    // Hook EVP_EncryptUpdate
    try {
        const evp_encrypt_update = Module.findExportByName("libcrypto.so", "EVP_EncryptUpdate");
        if (evp_encrypt_update) {
            Interceptor.attach(evp_encrypt_update, {
                onEnter: function(args) {
                    console.log("\n[+] EVP_EncryptUpdate called");
                    console.log("[-] Context:", args[0]);
                    console.log("[-] Out:", args[1]);
                    console.log("[-] Outl:", args[2]);
                    console.log("[-] In:", args[3]);
                    console.log("[-] Inl:", args[4]);
                    
                    // Extract input data
                    try {
                        const inLen = parseInt(args[4]);
                        if (inLen > 0 && inLen < 10000) { // Reasonable size limit
                            const inData = Memory.readByteArray(args[3], inLen);
                            const inHex = bytesToHex(inData);
                            const inBase64 = bytesToBase64(inData);
                            
                            console.log("[-] Input Data:");
                            console.log("    Hex:", inHex);
                            console.log("    Base64:", inBase64);
                            console.log("    Size:", inLen, "bytes");
                            
                            encryptedData.push({
                                type: "input",
                                hex: inHex,
                                base64: inBase64,
                                size: inLen,
                                timestamp: new Date().toISOString()
                            });
                        }
                    } catch (e) {
                        console.log("[-] Error reading input data:", e.message);
                    }
                },
                onLeave: function(retval) {
                    // Extract output data
                    try {
                        const outLen = parseInt(Memory.readInt(args[2]));
                        if (outLen > 0 && outLen < 10000) {
                            const outData = Memory.readByteArray(args[1], outLen);
                            const outHex = bytesToHex(outData);
                            const outBase64 = bytesToBase64(outData);
                            
                            console.log("[-] Output Data:");
                            console.log("    Hex:", outHex);
                            console.log("    Base64:", outBase64);
                            console.log("    Size:", outLen, "bytes");
                            
                            encryptedData.push({
                                type: "output",
                                hex: outHex,
                                base64: outBase64,
                                size: outLen,
                                timestamp: new Date().toISOString()
                            });
                        }
                    } catch (e) {
                        console.log("[-] Error reading output data:", e.message);
                    }
                }
            });
            console.log("[+] EVP_EncryptUpdate hooked successfully");
        }
    } catch (e) {
        console.log("[-] Error hooking EVP_EncryptUpdate:", e.message);
    }
}

// Hook libgojni specific functions
function hookLibGojni() {
    console.log("[+] Hooking libgojni functions...");
    
    // Wait for libgojni to be loaded
    Process.enumerateModules().forEach(function(module) {
        if (module.name.toLowerCase().includes("libgojni")) {
            console.log("[+] Found libgojni module:", module.name, "at", module.base);
            
            // Hook common encryption function names
            const functionNames = [
                "AES_encrypt",
                "AES_decrypt", 
                "encrypt",
                "decrypt",
                "aes_encrypt",
                "aes_decrypt",
                "crypto_encrypt",
                "crypto_decrypt"
            ];
            
            functionNames.forEach(function(funcName) {
                try {
                    const funcAddr = Module.findExportByName(module.name, funcName);
                    if (funcAddr) {
                        console.log("[+] Found function:", funcName, "at", funcAddr);
                        
                        Interceptor.attach(funcAddr, {
                            onEnter: function(args) {
                                console.log(`\n[+] ${funcName} called in libgojni`);
                                console.log("[-] Arguments count:", this.context.args.length);
                                
                                // Log all arguments
                                for (let i = 0; i < this.context.args.length; i++) {
                                    console.log(`[-] Arg[${i}]:`, this.context.args[i]);
                                }
                                
                                // Try to extract key and IV from arguments
                                this.context.args.forEach(function(arg, index) {
                                    try {
                                        // Try to read as potential key/IV data
                                        const data = Memory.readByteArray(arg, 32);
                                        if (data) {
                                            const hex = bytesToHex(data);
                                            const base64 = bytesToBase64(data);
                                            console.log(`[-] Potential key/IV at arg[${index}]:`, hex);
                                            
                                            // Store if it looks like a key (32 bytes) or IV (16 bytes)
                                            if (data.length >= 16) {
                                                const size = data.length >= 32 ? 32 : 16;
                                                const extractedData = data.slice(0, size);
                                                const extractedHex = bytesToHex(extractedData);
                                                const extractedBase64 = bytesToBase64(extractedData);
                                                
                                                if (size === 32) {
                                                    extractedKeys.push({
                                                        hex: extractedHex,
                                                        base64: extractedBase64,
                                                        size: size,
                                                        source: funcName,
                                                        timestamp: new Date().toISOString()
                                                    });
                                                } else {
                                                    extractedIVs.push({
                                                        hex: extractedHex,
                                                        base64: extractedBase64,
                                                        size: size,
                                                        source: funcName,
                                                        timestamp: new Date().toISOString()
                                                    });
                                                }
                                            }
                                        }
                                    } catch (e) {
                                        // Ignore errors for non-pointer arguments
                                    }
                                });
                            }
                        });
                    }
                } catch (e) {
                    // Function not found, continue
                }
            });
        }
    });
}

// Hook memory allocation functions to catch key/IV allocation
function hookMemoryAllocation() {
    console.log("[+] Hooking memory allocation functions...");
    
    // Hook malloc
    try {
        const malloc = Module.findExportByName("libc.so", "malloc");
        if (malloc) {
            Interceptor.attach(malloc, {
                onLeave: function(retval) {
                    const size = parseInt(this.context.args[0]);
                    
                    // Check if this might be a key or IV allocation
                    if (size === 16 || size === 24 || size === 32) {
                        console.log(`\n[+] Potential key/IV allocation: ${size} bytes at ${retval}`);
                        
                        // Store the address for later monitoring
                        setTimeout(function() {
                            try {
                                const data = Memory.readByteArray(retval, size);
                                if (data) {
                                    const hex = bytesToHex(data);
                                    const base64 = bytesToBase64(data);
                                    
                                    console.log(`[-] Data at ${retval}:`);
                                    console.log("    Hex:", hex);
                                    console.log("    Base64:", base64);
                                    
                                    if (size === 32) {
                                        extractedKeys.push({
                                            hex: hex,
                                            base64: base64,
                                            size: size,
                                            source: "malloc",
                                            address: retval,
                                            timestamp: new Date().toISOString()
                                        });
                                    } else {
                                        extractedIVs.push({
                                            hex: hex,
                                            base64: base64,
                                            size: size,
                                            source: "malloc",
                                            address: retval,
                                            timestamp: new Date().toISOString()
                                        });
                                    }
                                }
                            } catch (e) {
                                // Memory already freed or invalid
                            }
                        }, 100);
                    }
                }
            });
            console.log("[+] malloc hooked successfully");
        }
    } catch (e) {
        console.log("[-] Error hooking malloc:", e.message);
    }
}

// Function to print summary of extracted data
function printSummary() {
    console.log("\n" + "=".repeat(60));
    console.log("EXTRACTION SUMMARY");
    console.log("=".repeat(60));
    
    console.log(`\nExtracted Keys (${extractedKeys.length}):`);
    extractedKeys.forEach(function(key, index) {
        console.log(`\nKey ${index + 1}:`);
        console.log(`  Hex: ${key.hex}`);
        console.log(`  Base64: ${key.base64}`);
        console.log(`  Size: ${key.size} bytes`);
        console.log(`  Source: ${key.source || 'unknown'}`);
        console.log(`  Timestamp: ${key.timestamp}`);
    });
    
    console.log(`\nExtracted IVs (${extractedIVs.length}):`);
    extractedIVs.forEach(function(iv, index) {
        console.log(`\nIV ${index + 1}:`);
        console.log(`  Hex: ${iv.hex}`);
        console.log(`  Base64: ${iv.base64}`);
        console.log(`  Size: ${iv.size} bytes`);
        console.log(`  Source: ${iv.source || 'unknown'}`);
        console.log(`  Timestamp: ${iv.timestamp}`);
    });
    
    console.log(`\nEncrypted Data (${encryptedData.length}):`);
    encryptedData.forEach(function(data, index) {
        console.log(`\nData ${index + 1} (${data.type}):`);
        console.log(`  Hex: ${data.hex}`);
        console.log(`  Base64: ${data.base64}`);
        console.log(`  Size: ${data.size} bytes`);
        console.log(`  Timestamp: ${data.timestamp}`);
    });
    
    console.log("\n" + "=".repeat(60));
}

// Export functions for manual calls
global.extractSummary = printSummary;
global.getExtractedKeys = function() { return extractedKeys; };
global.getExtractedIVs = function() { return extractedIVs; };
global.getEncryptedData = function() { return encryptedData; };

// Main execution
setTimeout(function() {
    console.log("[+] Starting AES hooking...");
    
    // Hook OpenSSL functions
    hookOpenSSLAES();
    
    // Hook EVP functions
    hookEVPAES();
    
    // Hook libgojni functions
    hookLibGojni();
    
    // Hook memory allocation
    hookMemoryAllocation();
    
    console.log("[+] All hooks installed successfully");
    console.log("[+] Use 'extractSummary()' to see extracted data");
    console.log("[+] Use 'getExtractedKeys()', 'getExtractedIVs()', 'getEncryptedData()' for data access");
    
}, 1000);

// Print summary every 30 seconds
setInterval(printSummary, 30000);

console.log("[+] AES Hook Script Setup Complete");