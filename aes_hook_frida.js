/*
 * Frida Script for Hooking AES Functions in libgojni
 * این اسکریپت برای هوک کردن توابع AES در کتابخانه libgojni و استخراج کلید و IV طراحی شده است
 * 
 * Features:
 * - Hooks AES encryption/decryption functions
 * - Extracts keys and IVs
 * - Logs function calls with parameters
 * - Supports different AES modes (ECB, CBC, GCM, etc.)
 * - Memory dump capabilities
 */

console.log("[+] AES Hook Script Loaded");
console.log("[+] Starting to hook libgojni AES functions...");

// Global variables for tracking
let hookCount = 0;
let extractedKeys = new Set();
let extractedIVs = new Set();

// Utility functions
function hexdump(buffer, size) {
    if (!buffer) return "NULL";
    let result = "";
    const bytes = new Uint8Array(Memory.readByteArray(buffer, Math.min(size, 64)));
    for (let i = 0; i < bytes.length; i++) {
        if (i % 16 === 0) result += "\n";
        result += bytes[i].toString(16).padStart(2, '0') + " ";
    }
    return result;
}

function arrayToHex(array) {
    if (!array) return "NULL";
    let result = "";
    for (let i = 0; i < array.length; i++) {
        result += array[i].toString(16).padStart(2, '0') + " ";
    }
    return result;
}

function logWithTimestamp(message) {
    const now = new Date();
    console.log(`[${now.toISOString()}] ${message}`);
}

// Hook AES encryption functions
function hookAESEncrypt() {
    try {
        // Hook AES_encrypt (single block)
        const AES_encrypt = Module.findExportByName("libgojni.so", "AES_encrypt");
        if (AES_encrypt) {
            Interceptor.attach(AES_encrypt, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] AES_encrypt called`);
                    
                    // Extract key (usually 16, 24, or 32 bytes)
                    const key = args[0];
                    const plaintext = args[1];
                    const ciphertext = args[2];
                    
                    if (key && !ptr(key).isNull()) {
                        const keyData = Memory.readByteArray(key, 32);
                        if (keyData) {
                            const keyHex = arrayToHex(new Uint8Array(keyData));
                            logWithTimestamp(`[KEY] AES Key: ${keyHex}`);
                            extractedKeys.add(keyHex);
                        }
                    }
                    
                    if (plaintext && !ptr(plaintext).isNull()) {
                        const plainData = Memory.readByteArray(plaintext, 16);
                        if (plainData) {
                            logWithTimestamp(`[DATA] Plaintext: ${arrayToHex(new Uint8Array(plainData))}`);
                        }
                    }
                    
                    if (ciphertext && !ptr(ciphertext).isNull()) {
                        const cipherData = Memory.readByteArray(ciphertext, 16);
                        if (cipherData) {
                            logWithTimestamp(`[DATA] Ciphertext: ${arrayToHex(new Uint8Array(cipherData))}`);
                        }
                    }
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] AES_encrypt returned: ${retval}`);
                }
            });
            console.log("[+] Hooked AES_encrypt");
        }
    } catch (e) {
        console.log(`[-] Error hooking AES_encrypt: ${e}`);
    }
}

// Hook AES decryption functions
function hookAESDecrypt() {
    try {
        // Hook AES_decrypt (single block)
        const AES_decrypt = Module.findExportByName("libgojni.so", "AES_decrypt");
        if (AES_decrypt) {
            Interceptor.attach(AES_decrypt, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] AES_decrypt called`);
                    
                    const key = args[0];
                    const ciphertext = args[1];
                    const plaintext = args[2];
                    
                    if (key && !ptr(key).isNull()) {
                        const keyData = Memory.readByteArray(key, 32);
                        if (keyData) {
                            const keyHex = arrayToHex(new Uint8Array(keyData));
                            logWithTimestamp(`[KEY] AES Key: ${keyHex}`);
                            extractedKeys.add(keyHex);
                        }
                    }
                    
                    if (ciphertext && !ptr(ciphertext).isNull()) {
                        const cipherData = Memory.readByteArray(ciphertext, 16);
                        if (cipherData) {
                            logWithTimestamp(`[DATA] Ciphertext: ${arrayToHex(new Uint8Array(cipherData))}`);
                        }
                    }
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] AES_decrypt returned: ${retval}`);
                }
            });
            console.log("[+] Hooked AES_decrypt");
        }
    } catch (e) {
        console.log(`[-] Error hooking AES_decrypt: ${e}`);
    }
}

// Hook AES CBC mode functions
function hookAESCBC() {
    try {
        // Hook AES_cbc_encrypt
        const AES_cbc_encrypt = Module.findExportByName("libgojni.so", "AES_cbc_encrypt");
        if (AES_cbc_encrypt) {
            Interceptor.attach(AES_cbc_encrypt, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] AES_cbc_encrypt called`);
                    
                    const in_data = args[0];
                    const out_data = args[1];
                    const length = args[2].toInt32();
                    const key = args[3];
                    const ivec = args[4];
                    const enc = args[5].toInt32();
                    
                    logWithTimestamp(`[INFO] Length: ${length}, Encrypt: ${enc}`);
                    
                    // Extract key
                    if (key && !ptr(key).isNull()) {
                        const keyData = Memory.readByteArray(key, 32);
                        if (keyData) {
                            const keyHex = arrayToHex(new Uint8Array(keyData));
                            logWithTimestamp(`[KEY] AES Key: ${keyHex}`);
                            extractedKeys.add(keyHex);
                        }
                    }
                    
                    // Extract IV
                    if (ivec && !ptr(ivec).isNull()) {
                        const ivData = Memory.readByteArray(ivec, 16);
                        if (ivData) {
                            const ivHex = arrayToHex(new Uint8Array(ivData));
                            logWithTimestamp(`[IV] Initialization Vector: ${ivHex}`);
                            extractedIVs.add(ivHex);
                        }
                    }
                    
                    // Log data samples
                    if (in_data && !ptr(in_data).isNull() && length > 0) {
                        const sampleSize = Math.min(length, 32);
                        const inSample = Memory.readByteArray(in_data, sampleSize);
                        if (inSample) {
                            logWithTimestamp(`[DATA] Input sample: ${arrayToHex(new Uint8Array(inSample))}`);
                        }
                    }
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] AES_cbc_encrypt returned: ${retval}`);
                }
            });
            console.log("[+] Hooked AES_cbc_encrypt");
        }
        
        // Hook AES_cbc_decrypt
        const AES_cbc_decrypt = Module.findExportByName("libgojni.so", "AES_cbc_decrypt");
        if (AES_cbc_decrypt) {
            Interceptor.attach(AES_cbc_decrypt, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] AES_cbc_decrypt called`);
                    
                    const in_data = args[0];
                    const out_data = args[1];
                    const length = args[2].toInt32();
                    const key = args[3];
                    const ivec = args[4];
                    
                    logWithTimestamp(`[INFO] Length: ${length}`);
                    
                    // Extract key
                    if (key && !ptr(key).isNull()) {
                        const keyData = Memory.readByteArray(key, 32);
                        if (keyData) {
                            const keyHex = arrayToHex(new Uint8Array(keyData));
                            logWithTimestamp(`[KEY] AES Key: ${keyHex}`);
                            extractedKeys.add(keyHex);
                        }
                    }
                    
                    // Extract IV
                    if (ivec && !ptr(ivec).isNull()) {
                        const ivData = Memory.readByteArray(ivec, 16);
                        if (ivData) {
                            const ivHex = arrayToHex(new Uint8Array(ivData));
                            logWithTimestamp(`[IV] Initialization Vector: ${ivHex}`);
                            extractedIVs.add(ivHex);
                        }
                    }
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] AES_cbc_decrypt returned: ${retval}`);
                }
            });
            console.log("[+] Hooked AES_cbc_decrypt");
        }
    } catch (e) {
        console.log(`[-] Error hooking AES CBC functions: ${e}`);
    }
}

// Hook AES GCM mode functions
function hookAESGCM() {
    try {
        // Hook AES_gcm_encrypt
        const AES_gcm_encrypt = Module.findExportByName("libgojni.so", "AES_gcm_encrypt");
        if (AES_gcm_encrypt) {
            Interceptor.attach(AES_gcm_encrypt, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] AES_gcm_encrypt called`);
                    
                    const key = args[0];
                    const iv = args[1];
                    const plaintext = args[2];
                    const plaintext_len = args[3].toInt32();
                    const ciphertext = args[4];
                    const tag = args[5];
                    
                    logWithTimestamp(`[INFO] Plaintext length: ${plaintext_len}`);
                    
                    // Extract key
                    if (key && !ptr(key).isNull()) {
                        const keyData = Memory.readByteArray(key, 32);
                        if (keyData) {
                            const keyHex = arrayToHex(new Uint8Array(keyData));
                            logWithTimestamp(`[KEY] AES Key: ${keyHex}`);
                            extractedKeys.add(keyHex);
                        }
                    }
                    
                    // Extract IV
                    if (iv && !ptr(iv).isNull()) {
                        const ivData = Memory.readByteArray(iv, 16);
                        if (ivData) {
                            const ivHex = arrayToHex(new Uint8Array(ivData));
                            logWithTimestamp(`[IV] GCM IV: ${ivHex}`);
                            extractedIVs.add(ivHex);
                        }
                    }
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] AES_gcm_encrypt returned: ${retval}`);
                }
            });
            console.log("[+] Hooked AES_gcm_encrypt");
        }
        
        // Hook AES_gcm_decrypt
        const AES_gcm_decrypt = Module.findExportByName("libgojni.so", "AES_gcm_decrypt");
        if (AES_gcm_decrypt) {
            Interceptor.attach(AES_gcm_decrypt, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] AES_gcm_decrypt called`);
                    
                    const key = args[0];
                    const iv = args[1];
                    const ciphertext = args[2];
                    const ciphertext_len = args[3].toInt32();
                    const plaintext = args[4];
                    const tag = args[5];
                    
                    logWithTimestamp(`[INFO] Ciphertext length: ${ciphertext_len}`);
                    
                    // Extract key
                    if (key && !ptr(key).isNull()) {
                        const keyData = Memory.readByteArray(key, 32);
                        if (keyData) {
                            const keyHex = arrayToHex(new Uint8Array(keyData));
                            logWithTimestamp(`[KEY] AES Key: ${keyHex}`);
                            extractedKeys.add(keyHex);
                        }
                    }
                    
                    // Extract IV
                    if (iv && !ptr(iv).isNull()) {
                        const ivData = Memory.readByteArray(iv, 16);
                        if (ivData) {
                            const ivHex = arrayToHex(new Uint8Array(ivData));
                            logWithTimestamp(`[IV] GCM IV: ${ivHex}`);
                            extractedIVs.add(ivHex);
                        }
                    }
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] AES_gcm_decrypt returned: ${retval}`);
                }
            });
            console.log("[+] Hooked AES_gcm_decrypt");
        }
    } catch (e) {
        console.log(`[-] Error hooking AES GCM functions: ${e}`);
    }
}

// Hook AES key generation functions
function hookAESKeyGen() {
    try {
        // Hook AES_set_encrypt_key
        const AES_set_encrypt_key = Module.findExportByName("libgojni.so", "AES_set_encrypt_key");
        if (AES_set_encrypt_key) {
            Interceptor.attach(AES_set_encrypt_key, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] AES_set_encrypt_key called`);
                    
                    const userKey = args[0];
                    const bits = args[1].toInt32();
                    const key = args[2];
                    
                    logWithTimestamp(`[INFO] Key bits: ${bits}`);
                    
                    if (userKey && !ptr(userKey).isNull()) {
                        const keySize = bits / 8;
                        const keyData = Memory.readByteArray(userKey, keySize);
                        if (keyData) {
                            const keyHex = arrayToHex(new Uint8Array(keyData));
                            logWithTimestamp(`[KEY] User Key: ${keyHex}`);
                            extractedKeys.add(keyHex);
                        }
                    }
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] AES_set_encrypt_key returned: ${retval}`);
                }
            });
            console.log("[+] Hooked AES_set_encrypt_key");
        }
        
        // Hook AES_set_decrypt_key
        const AES_set_decrypt_key = Module.findExportByName("libgojni.so", "AES_set_decrypt_key");
        if (AES_set_decrypt_key) {
            Interceptor.attach(AES_set_decrypt_key, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] AES_set_decrypt_key called`);
                    
                    const userKey = args[0];
                    const bits = args[1].toInt32();
                    const key = args[2];
                    
                    logWithTimestamp(`[INFO] Key bits: ${bits}`);
                    
                    if (userKey && !ptr(userKey).isNull()) {
                        const keySize = bits / 8;
                        const keyData = Memory.readByteArray(userKey, keySize);
                        if (keyData) {
                            const keyHex = arrayToHex(new Uint8Array(keyData));
                            logWithTimestamp(`[KEY] User Key: ${keyHex}`);
                            extractedKeys.add(keyHex);
                        }
                    }
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] AES_set_decrypt_key returned: ${retval}`);
                }
            });
            console.log("[+] Hooked AES_set_decrypt_key");
        }
    } catch (e) {
        console.log(`[-] Error hooking AES key generation functions: ${e}`);
    }
}

// Hook EVP functions (OpenSSL wrapper)
function hookEVPAES() {
    try {
        // Hook EVP_aes_256_cbc
        const EVP_aes_256_cbc = Module.findExportByName("libgojni.so", "EVP_aes_256_cbc");
        if (EVP_aes_256_cbc) {
            Interceptor.attach(EVP_aes_256_cbc, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] EVP_aes_256_cbc called`);
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] EVP_aes_256_cbc returned: ${retval}`);
                }
            });
            console.log("[+] Hooked EVP_aes_256_cbc");
        }
        
        // Hook EVP_aes_128_cbc
        const EVP_aes_128_cbc = Module.findExportByName("libgojni.so", "EVP_aes_128_cbc");
        if (EVP_aes_128_cbc) {
            Interceptor.attach(EVP_aes_128_cbc, {
                onEnter: function(args) {
                    hookCount++;
                    logWithTimestamp(`[${hookCount}] EVP_aes_128_cbc called`);
                },
                onLeave: function(retval) {
                    logWithTimestamp(`[${hookCount}] EVP_aes_128_cbc returned: ${retval}`);
                }
            });
            console.log("[+] Hooked EVP_aes_128_cbc");
        }
    } catch (e) {
        console.log(`[-] Error hooking EVP AES functions: ${e}`);
    }
}

// Hook JNI functions that might call AES
function hookJNIAES() {
    try {
        // Hook common JNI function names that might contain AES
        const jniFunctions = [
            "Java_com_example_encrypt",
            "Java_com_example_decrypt",
            "Java_com_example_AES",
            "Java_com_example_crypto"
        ];
        
        jniFunctions.forEach(funcName => {
            const func = Module.findExportByName("libgojni.so", funcName);
            if (func) {
                Interceptor.attach(func, {
                    onEnter: function(args) {
                        hookCount++;
                        logWithTimestamp(`[${hookCount}] ${funcName} called`);
                        
                        // Try to extract parameters that might be keys or IVs
                        for (let i = 0; i < 5; i++) {
                            const arg = args[i];
                            if (arg && !ptr(arg).isNull()) {
                                try {
                                    const data = Memory.readByteArray(arg, 32);
                                    if (data) {
                                        const hexData = arrayToHex(new Uint8Array(data));
                                        logWithTimestamp(`[PARAM] Arg${i}: ${hexData}`);
                                    }
                                } catch (e) {
                                    // Ignore invalid memory reads
                                }
                            }
                        }
                    },
                    onLeave: function(retval) {
                        logWithTimestamp(`[${hookCount}] ${funcName} returned: ${retval}`);
                    }
                });
                console.log(`[+] Hooked ${funcName}`);
            }
        });
    } catch (e) {
        console.log(`[-] Error hooking JNI AES functions: ${e}`);
    }
}

// Memory scanning for AES keys
function scanForAESKeys() {
    try {
        console.log("[+] Scanning memory for potential AES keys...");
        
        // Common AES key patterns
        const keyPatterns = [
            // 16 bytes (128-bit)
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            // 24 bytes (192-bit)
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17],
            // 32 bytes (256-bit)
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]
        ];
        
        // Scan for patterns in memory ranges
        Process.enumerateRanges('r--').forEach(range => {
            try {
                const data = Memory.readByteArray(range.base, Math.min(range.size, 1024 * 1024));
                if (data) {
                    const bytes = new Uint8Array(data);
                    
                    // Look for potential keys (non-zero bytes with some entropy)
                    for (let i = 0; i < bytes.length - 32; i++) {
                        let entropy = 0;
                        for (let j = 0; j < 32; j++) {
                            if (bytes[i + j] !== 0) entropy++;
                        }
                        
                        if (entropy > 20) { // At least 20 non-zero bytes
                            const potentialKey = bytes.slice(i, i + 32);
                            const keyHex = arrayToHex(potentialKey);
                            logWithTimestamp(`[SCAN] Potential key at ${range.base.add(i)}: ${keyHex}`);
                        }
                    }
                }
            } catch (e) {
                // Ignore memory read errors
            }
        });
        
        console.log("[+] Memory scan completed");
    } catch (e) {
        console.log(`[-] Error scanning memory: ${e}`);
    }
}

// Main execution
function main() {
    console.log("[+] Starting AES hook script...");
    
    // Wait for libgojni to be loaded
    Process.enumerateModules().forEach(module => {
        if (module.name.includes("libgojni")) {
            console.log(`[+] Found libgojni at: ${module.base}`);
            
            // Hook all AES functions
            hookAESEncrypt();
            hookAESDecrypt();
            hookAESCBC();
            hookAESGCM();
            hookAESKeyGen();
            hookEVPAES();
            hookJNIAES();
            
            // Scan for keys in memory
            setTimeout(scanForAESKeys, 2000);
            
            return;
        }
    });
    
    // If libgojni not found, try to hook anyway
    if (hookCount === 0) {
        console.log("[!] libgojni not found, trying to hook anyway...");
        hookAESEncrypt();
        hookAESDecrypt();
        hookAESCBC();
        hookAESGCM();
        hookAESKeyGen();
        hookEVPAES();
        hookJNIAES();
    }
    
    // Periodic summary
    setInterval(() => {
        console.log(`[SUMMARY] Total hooks: ${hookCount}, Unique keys: ${extractedKeys.size}, Unique IVs: ${extractedIVs.size}`);
        if (extractedKeys.size > 0) {
            console.log("[KEYS FOUND]:");
            extractedKeys.forEach(key => console.log(`  ${key}`));
        }
        if (extractedIVs.size > 0) {
            console.log("[IVS FOUND]:");
            extractedIVs.forEach(iv => console.log(`  ${iv}`));
        }
    }, 10000);
}

// Export functions for manual use
global.aesHook = {
    scanForKeys: scanForAESKeys,
    getExtractedKeys: () => Array.from(extractedKeys),
    getExtractedIVs: () => Array.from(extractedIVs),
    getHookCount: () => hookCount
};

// Start the script
main();

console.log("[+] AES Hook Script initialization complete");
console.log("[+] Use global.aesHook to access extracted data");