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

// Global variables to store extracted data
var extractedKeys = [];
var extractedIVs = [];
var functionCalls = [];

// Utility function to convert byte array to hex string
function bytesToHex(bytes) {
    if (!bytes) return "null";
    return Array.from(bytes, byte => ('0' + (byte & 0xFF).toString(16)).slice(-2)).join('');
}

// Utility function to convert hex string to byte array
function hexToBytes(hex) {
    if (!hex) return null;
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// Utility function to convert byte array to base64
function bytesToBase64(bytes) {
    if (!bytes) return "null";
    return btoa(String.fromCharCode.apply(null, bytes));
}

// Utility function to dump memory region
function dumpMemory(address, size) {
    try {
        return Memory.readByteArray(ptr(address), size);
    } catch (e) {
        console.log("[-] Failed to dump memory at " + address + ": " + e.message);
        return null;
    }
}

// Function to log extracted data
function logExtractedData(functionName, key, iv, data, additionalInfo = {}) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        function: functionName,
        key: key ? bytesToHex(key) : "null",
        key_base64: key ? bytesToBase64(key) : "null",
        iv: iv ? bytesToHex(iv) : "null",
        iv_base64: iv ? bytesToBase64(iv) : "null",
        data_length: data ? data.length : 0,
        data_preview: data ? bytesToHex(data.slice(0, 32)) : "null",
        ...additionalInfo
    };
    
    functionCalls.push(logEntry);
    
    console.log("=== AES Function Call Detected ===");
    console.log("Function: " + functionName);
    console.log("Key (hex): " + logEntry.key);
    console.log("Key (base64): " + logEntry.key_base64);
    console.log("IV (hex): " + logEntry.iv);
    console.log("IV (base64): " + logEntry.iv_base64);
    console.log("Data Length: " + logEntry.data_length);
    console.log("Data Preview: " + logEntry.data_preview);
    console.log("Additional Info: " + JSON.stringify(additionalInfo));
    console.log("==================================");
    
    // Store unique keys and IVs
    if (key && !extractedKeys.some(k => bytesToHex(k) === bytesToHex(key))) {
        extractedKeys.push(key);
    }
    if (iv && !extractedIVs.some(i => bytesToHex(i) === bytesToHex(iv))) {
        extractedIVs.push(iv);
    }
}

// Hook for AES encryption functions
function hookAESEncrypt() {
    try {
        // Hook common AES encryption function names
        const encryptFunctions = [
            "AES_encrypt",
            "AES_ecb_encrypt", 
            "AES_cbc_encrypt",
            "AES_cfb_encrypt",
            "AES_ofb_encrypt",
            "AES_ctr_encrypt",
            "AES_gcm_encrypt",
            "EVP_EncryptInit_ex",
            "EVP_EncryptUpdate",
            "EVP_EncryptFinal_ex"
        ];
        
        encryptFunctions.forEach(funcName => {
            try {
                const funcAddr = Module.findExportByName("libgojni.so", funcName);
                if (funcAddr) {
                    console.log("[+] Found " + funcName + " at " + funcAddr);
                    
                    Interceptor.attach(funcAddr, {
                        onEnter: function(args) {
                            this.funcName = funcName;
                            this.args = args;
                            
                            try {
                                // Extract parameters based on function signature
                                let key = null;
                                let iv = null;
                                let data = null;
                                
                                switch(funcName) {
                                    case "AES_encrypt":
                                    case "AES_ecb_encrypt":
                                        // AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
                                        if (args[0] && args[1] && args[2]) {
                                            data = Memory.readByteArray(args[0], 16); // AES block size
                                            key = this.extractKeyFromAESKey(args[2]);
                                        }
                                        break;
                                        
                                    case "AES_cbc_encrypt":
                                        // AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, int enc)
                                        if (args[0] && args[1] && args[3] && args[4]) {
                                            const length = args[2].toInt32();
                                            data = Memory.readByteArray(args[0], length);
                                            key = this.extractKeyFromAESKey(args[3]);
                                            iv = Memory.readByteArray(args[4], 16);
                                        }
                                        break;
                                        
                                    case "EVP_EncryptInit_ex":
                                        // EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, const unsigned char *key, const unsigned char *iv)
                                        if (args[3] && args[4]) {
                                            key = Memory.readByteArray(args[3], 32); // Assuming AES-256
                                            iv = Memory.readByteArray(args[4], 16);
                                        }
                                        break;
                                        
                                    case "EVP_EncryptUpdate":
                                        // EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
                                        if (args[3] && args[4]) {
                                            const inl = args[4].toInt32();
                                            data = Memory.readByteArray(args[3], inl);
                                        }
                                        break;
                                }
                                
                                if (key || iv || data) {
                                    logExtractedData(funcName, key, iv, data, {
                                        address: this.returnAddress.toString(),
                                        thread_id: Process.getCurrentThreadId()
                                    });
                                }
                                
                            } catch (e) {
                                console.log("[-] Error in " + funcName + " hook: " + e.message);
                            }
                        },
                        
                        extractKeyFromAESKey: function(aesKeyPtr) {
                            try {
                                // AES_KEY structure typically contains the key material
                                // This is a simplified extraction - actual structure may vary
                                return Memory.readByteArray(aesKeyPtr, 256); // Read potential key area
                            } catch (e) {
                                return null;
                            }
                        }
                    });
                }
            } catch (e) {
                console.log("[-] Error hooking " + funcName + ": " + e.message);
            }
        });
        
    } catch (e) {
        console.log("[-] Error in hookAESEncrypt: " + e.message);
    }
}

// Hook for AES decryption functions
function hookAESDecrypt() {
    try {
        const decryptFunctions = [
            "AES_decrypt",
            "AES_ecb_decrypt",
            "AES_cbc_decrypt", 
            "AES_cfb_decrypt",
            "AES_ofb_decrypt",
            "AES_ctr_decrypt",
            "AES_gcm_decrypt",
            "EVP_DecryptInit_ex",
            "EVP_DecryptUpdate",
            "EVP_DecryptFinal_ex"
        ];
        
        decryptFunctions.forEach(funcName => {
            try {
                const funcAddr = Module.findExportByName("libgojni.so", funcName);
                if (funcAddr) {
                    console.log("[+] Found " + funcName + " at " + funcAddr);
                    
                    Interceptor.attach(funcAddr, {
                        onEnter: function(args) {
                            this.funcName = funcName;
                            this.args = args;
                            
                            try {
                                let key = null;
                                let iv = null;
                                let data = null;
                                
                                switch(funcName) {
                                    case "AES_decrypt":
                                    case "AES_ecb_decrypt":
                                        if (args[0] && args[1] && args[2]) {
                                            data = Memory.readByteArray(args[0], 16);
                                            key = this.extractKeyFromAESKey(args[2]);
                                        }
                                        break;
                                        
                                    case "AES_cbc_decrypt":
                                        if (args[0] && args[1] && args[3] && args[4]) {
                                            const length = args[2].toInt32();
                                            data = Memory.readByteArray(args[0], length);
                                            key = this.extractKeyFromAESKey(args[3]);
                                            iv = Memory.readByteArray(args[4], 16);
                                        }
                                        break;
                                        
                                    case "EVP_DecryptInit_ex":
                                        if (args[3] && args[4]) {
                                            key = Memory.readByteArray(args[3], 32);
                                            iv = Memory.readByteArray(args[4], 16);
                                        }
                                        break;
                                        
                                    case "EVP_DecryptUpdate":
                                        if (args[3] && args[4]) {
                                            const inl = args[4].toInt32();
                                            data = Memory.readByteArray(args[3], inl);
                                        }
                                        break;
                                }
                                
                                if (key || iv || data) {
                                    logExtractedData(funcName, key, iv, data, {
                                        address: this.returnAddress.toString(),
                                        thread_id: Process.getCurrentThreadId()
                                    });
                                }
                                
                            } catch (e) {
                                console.log("[-] Error in " + funcName + " hook: " + e.message);
                            }
                        },
                        
                        extractKeyFromAESKey: function(aesKeyPtr) {
                            try {
                                return Memory.readByteArray(aesKeyPtr, 256);
                            } catch (e) {
                                return null;
                            }
                        }
                    });
                }
            } catch (e) {
                console.log("[-] Error hooking " + funcName + ": " + e.message);
            }
        });
        
    } catch (e) {
        console.log("[-] Error in hookAESDecrypt: " + e.message);
    }
}

// Hook for key generation functions
function hookKeyGeneration() {
    try {
        const keyGenFunctions = [
            "AES_set_encrypt_key",
            "AES_set_decrypt_key",
            "EVP_BytesToKey",
            "PKCS5_PBKDF2_HMAC"
        ];
        
        keyGenFunctions.forEach(funcName => {
            try {
                const funcAddr = Module.findExportByName("libgojni.so", funcName);
                if (funcAddr) {
                    console.log("[+] Found " + funcName + " at " + funcAddr);
                    
                    Interceptor.attach(funcAddr, {
                        onEnter: function(args) {
                            this.funcName = funcName;
                            this.args = args;
                            
                            try {
                                let key = null;
                                let salt = null;
                                
                                switch(funcName) {
                                    case "AES_set_encrypt_key":
                                    case "AES_set_decrypt_key":
                                        // AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
                                        if (args[0] && args[2]) {
                                            const bits = args[1].toInt32();
                                            const keySize = bits / 8;
                                            key = Memory.readByteArray(args[0], keySize);
                                        }
                                        break;
                                        
                                    case "EVP_BytesToKey":
                                        // EVP_BytesToKey(const EVP_CIPHER *type, const EVP_MD *md, const unsigned char *salt, const unsigned char *data, int datal, int count, unsigned char *key, unsigned char *iv)
                                        if (args[2] && args[3] && args[6] && args[7]) {
                                            salt = Memory.readByteArray(args[2], 8);
                                            const data = Memory.readByteArray(args[3], args[4].toInt32());
                                            key = Memory.readByteArray(args[6], 32);
                                            const iv = Memory.readByteArray(args[7], 16);
                                            
                                            logExtractedData(funcName, key, iv, data, {
                                                salt: bytesToHex(salt),
                                                count: args[5].toInt32()
                                            });
                                        }
                                        break;
                                        
                                    case "PKCS5_PBKDF2_HMAC":
                                        // PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out)
                                        if (args[0] && args[2] && args[6]) {
                                            const passlen = args[1].toInt32();
                                            const password = Memory.readByteArray(args[0], passlen);
                                            salt = Memory.readByteArray(args[2], args[3].toInt32());
                                            const keylen = args[6].toInt32();
                                            key = Memory.readByteArray(args[6], keylen);
                                            
                                            logExtractedData(funcName, key, null, password, {
                                                salt: bytesToHex(salt),
                                                iterations: args[4].toInt32(),
                                                key_length: keylen
                                            });
                                        }
                                        break;
                                }
                                
                                if (key) {
                                    logExtractedData(funcName, key, null, null, {
                                        salt: salt ? bytesToHex(salt) : null
                                    });
                                }
                                
                            } catch (e) {
                                console.log("[-] Error in " + funcName + " hook: " + e.message);
                            }
                        }
                    });
                }
            } catch (e) {
                console.log("[-] Error hooking " + funcName + ": " + e.message);
            }
        });
        
    } catch (e) {
        console.log("[-] Error in hookKeyGeneration: " + e.message);
    }
}

// Hook for memory allocation functions to track key storage
function hookMemoryAllocation() {
    try {
        const allocFunctions = [
            "malloc",
            "calloc",
            "realloc",
            "free"
        ];
        
        allocFunctions.forEach(funcName => {
            try {
                const funcAddr = Module.findExportByName("libc.so", funcName);
                if (funcAddr) {
                    Interceptor.attach(funcAddr, {
                        onEnter: function(args) {
                            this.funcName = funcName;
                            this.args = args;
                        },
                        onLeave: function(retval) {
                            if (this.funcName === "malloc" || this.funcName === "calloc") {
                                const size = this.args[0].toInt32();
                                // If allocation size matches typical key sizes, monitor it
                                if (size === 16 || size === 24 || size === 32 || size === 256) {
                                    console.log("[+] Potential key allocation: " + this.funcName + " size=" + size + " addr=" + retval);
                                }
                            }
                        }
                    });
                }
            } catch (e) {
                // Ignore errors for memory allocation hooks
            }
        });
        
    } catch (e) {
        console.log("[-] Error in hookMemoryAllocation: " + e.message);
    }
}

// Function to export extracted data
function exportData() {
    const exportData = {
        timestamp: new Date().toISOString(),
        total_calls: functionCalls.length,
        unique_keys: extractedKeys.length,
        unique_ivs: extractedIVs.length,
        function_calls: functionCalls,
        unique_keys_hex: extractedKeys.map(k => bytesToHex(k)),
        unique_keys_base64: extractedKeys.map(k => bytesToBase64(k)),
        unique_ivs_hex: extractedIVs.map(i => bytesToHex(i)),
        unique_ivs_base64: extractedIVs.map(i => bytesToBase64(i))
    };
    
    console.log("[+] Exporting extracted data:");
    console.log(JSON.stringify(exportData, null, 2));
    
    return exportData;
}

// Main execution
try {
    // Wait for libgojni to be loaded
    Process.enumerateModules().forEach(function(module) {
        if (module.name.indexOf("libgojni") !== -1) {
            console.log("[+] Found libgojni.so at " + module.base);
            
            // Set up hooks
            hookAESEncrypt();
            hookAESDecrypt();
            hookKeyGeneration();
            hookMemoryAllocation();
            
            console.log("[+] All hooks installed successfully");
        }
    });
    
    // If libgojni is not loaded yet, wait for it
    if (!Process.enumerateModules().some(m => m.name.indexOf("libgojni") !== -1)) {
        console.log("[*] Waiting for libgojni.so to be loaded...");
        
        Process.enumerateModules().forEach(function(module) {
            if (module.name.indexOf("libgojni") !== -1) {
                console.log("[+] libgojni.so loaded at " + module.base);
                
                hookAESEncrypt();
                hookAESDecrypt();
                hookKeyGeneration();
                hookMemoryAllocation();
                
                console.log("[+] All hooks installed successfully");
            }
        });
    }
    
    // Export function for external access
    global.exportAESData = exportData;
    global.getExtractedKeys = function() { return extractedKeys; };
    global.getExtractedIVs = function() { return extractedIVs; };
    global.getFunctionCalls = function() { return functionCalls; };
    
    console.log("[+] Script loaded successfully. Use exportAESData() to get extracted data.");
    
} catch (e) {
    console.log("[-] Error in main execution: " + e.message);
    console.log(e.stack);
}