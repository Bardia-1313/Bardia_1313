/**
 * Frida Script for Hooking AES Functions in libgojni
 * Extracts AES keys and IVs from encryption/decryption operations
 * Author: Frida AES Hook Script
 */

// Helper function to convert byte array to hex string
function bytesToHex(bytes) {
    if (!bytes) return "null";
    let result = "";
    for (let i = 0; i < bytes.length; i++) {
        result += ("0" + bytes[i].toString(16)).slice(-2);
    }
    return result;
}

// Helper function to dump memory as hex
function dumpMemory(ptr, size, label) {
    if (!ptr || ptr.isNull()) {
        console.log(`[${label}] Null pointer`);
        return;
    }
    
    try {
        const data = ptr.readByteArray(size);
        console.log(`[${label}] Size: ${size} bytes`);
        console.log(`[${label}] Data: ${bytesToHex(new Uint8Array(data))}`);
        console.log(`[${label}] Address: ${ptr}`);
        return new Uint8Array(data);
    } catch (e) {
        console.log(`[${label}] Error reading memory: ${e}`);
    }
}

// Main hooking function
function hookAESFunctions() {
    console.log("[*] Starting AES function hooking for libgojni...");
    
    // Try to find libgojni library
    let libgojni = null;
    try {
        libgojni = Process.getModuleByName("libgojni.so");
        console.log(`[+] Found libgojni at: ${libgojni.base}`);
    } catch (e) {
        console.log("[-] libgojni.so not found, trying alternative names...");
        
        // Try alternative library names
        const alternatives = ["libgojni", "gojni", "libgo", "libcrypto"];
        for (let alt of alternatives) {
            try {
                libgojni = Process.getModuleByName(alt + ".so");
                console.log(`[+] Found library ${alt}.so at: ${libgojni.base}`);
                break;
            } catch (e2) {
                continue;
            }
        }
    }
    
    if (!libgojni) {
        console.log("[-] Could not find target library. Listing all loaded modules:");
        Process.enumerateModules().forEach(module => {
            if (module.name.toLowerCase().includes("go") || 
                module.name.toLowerCase().includes("crypto") ||
                module.name.toLowerCase().includes("jni")) {
                console.log(`    ${module.name} - ${module.base}`);
            }
        });
        return;
    }

    // Common AES function patterns to hook
    const aesPatterns = [
        // Standard AES function names
        "AES_encrypt",
        "AES_decrypt", 
        "AES_set_encrypt_key",
        "AES_set_decrypt_key",
        "AES_cbc_encrypt",
        "AES_cfb128_encrypt",
        "AES_ofb128_encrypt",
        "AES_ecb_encrypt",
        
        // OpenSSL AES functions
        "EVP_aes_128_cbc",
        "EVP_aes_192_cbc", 
        "EVP_aes_256_cbc",
        "EVP_aes_128_ecb",
        "EVP_aes_192_ecb",
        "EVP_aes_256_ecb",
        "EVP_EncryptInit",
        "EVP_EncryptInit_ex",
        "EVP_DecryptInit",
        "EVP_DecryptInit_ex",
        "EVP_CipherInit",
        "EVP_CipherInit_ex",
        
        // Android/Java crypto functions
        "Java_javax_crypto_Cipher_doFinal",
        "Java_javax_crypto_Cipher_update",
        
        // Go crypto functions (common patterns)
        "crypto_aes_encrypt",
        "crypto_aes_decrypt",
        "aes_encrypt",
        "aes_decrypt",
        "cipher_encrypt",
        "cipher_decrypt"
    ];

    let hookedCount = 0;

    // Try to hook each pattern
    aesPatterns.forEach(pattern => {
        try {
            const symbols = libgojni.enumerateSymbols().filter(symbol => 
                symbol.name.toLowerCase().includes(pattern.toLowerCase())
            );
            
            symbols.forEach(symbol => {
                console.log(`[+] Attempting to hook: ${symbol.name} at ${symbol.address}`);
                
                Interceptor.attach(symbol.address, {
                    onEnter: function(args) {
                        console.log(`\n[HOOK] ${symbol.name} called`);
                        console.log(`[INFO] Thread: ${this.threadId}`);
                        console.log(`[INFO] Address: ${symbol.address}`);
                        
                        // Log arguments
                        for (let i = 0; i < Math.min(6, args.length); i++) {
                            console.log(`[ARG${i}] ${args[i]}`);
                        }
                        
                        // Try to extract potential keys and IVs based on common patterns
                        this.extractCryptoData(args, symbol.name);
                    },
                    
                    onLeave: function(retval) {
                        console.log(`[RETURN] ${symbol.name} returned: ${retval}`);
                    },
                    
                    extractCryptoData: function(args, funcName) {
                        // Different extraction strategies based on function name
                        if (funcName.includes("set_encrypt_key") || funcName.includes("set_decrypt_key")) {
                            // args[0] usually contains the key, args[1] the key length
                            if (args[0] && !args[0].isNull()) {
                                const keyLen = args[1] ? args[1].toInt32() : 32;
                                dumpMemory(args[0], Math.min(keyLen, 64), "AES_KEY");
                            }
                        }
                        else if (funcName.includes("cbc") || funcName.includes("cfb") || funcName.includes("ofb")) {
                            // CBC/CFB/OFB modes typically have IV as one of the arguments
                            // Common pattern: func(input, output, length, key, iv)
                            if (args[3] && !args[3].isNull()) {
                                dumpMemory(args[3], 32, "POTENTIAL_KEY");
                            }
                            if (args[4] && !args[4].isNull()) {
                                dumpMemory(args[4], 16, "POTENTIAL_IV");
                            }
                        }
                        else if (funcName.includes("Init")) {
                            // EVP_*Init functions
                            // Common pattern: EVP_CipherInit_ex(ctx, cipher, impl, key, iv, enc)
                            if (args[3] && !args[3].isNull()) {
                                dumpMemory(args[3], 32, "EVP_KEY");
                            }
                            if (args[4] && !args[4].isNull()) {
                                dumpMemory(args[4], 16, "EVP_IV");
                            }
                        }
                        else {
                            // Generic approach - dump first few arguments that might be keys/IVs
                            for (let i = 0; i < Math.min(4, args.length); i++) {
                                if (args[i] && !args[i].isNull()) {
                                    try {
                                        // Try different sizes that are common for keys/IVs
                                        const sizes = [16, 24, 32]; // AES-128, AES-192, AES-256
                                        sizes.forEach(size => {
                                            dumpMemory(args[i], size, `ARG${i}_${size}BYTES`);
                                        });
                                    } catch (e) {
                                        // Continue if memory read fails
                                    }
                                }
                            }
                        }
                    }
                });
                
                hookedCount++;
            });
            
        } catch (e) {
            // Function not found or hook failed, continue
        }
    });

    // Also try to find and hook functions by scanning for AES-related patterns
    console.log("[*] Scanning for AES-related functions by pattern...");
    
    try {
        libgojni.enumerateSymbols().forEach(symbol => {
            const name = symbol.name.toLowerCase();
            if ((name.includes("aes") || name.includes("cipher") || name.includes("crypto")) &&
                (name.includes("encrypt") || name.includes("decrypt") || name.includes("init"))) {
                
                console.log(`[+] Found potential AES function: ${symbol.name}`);
                
                try {
                    Interceptor.attach(symbol.address, {
                        onEnter: function(args) {
                            console.log(`\n[SCAN_HOOK] ${symbol.name} called`);
                            
                            // Basic argument dumping
                            for (let i = 0; i < Math.min(4, args.length); i++) {
                                if (args[i] && !args[i].isNull()) {
                                    dumpMemory(args[i], 16, `${symbol.name}_ARG${i}`);
                                }
                            }
                        }
                    });
                    hookedCount++;
                } catch (e) {
                    // Hook failed, continue
                }
            }
        });
    } catch (e) {
        console.log(`[-] Error during symbol scanning: ${e}`);
    }

    console.log(`[*] Successfully hooked ${hookedCount} functions`);
    
    if (hookedCount === 0) {
        console.log("[-] No AES functions found. This might be due to:");
        console.log("    1. Functions being stripped from the binary");
        console.log("    2. Functions being inlined or optimized away");
        console.log("    3. Different naming convention");
        console.log("    4. Dynamic loading of crypto functions");
        console.log("\n[*] Trying alternative approaches...");
        
        // Try to hook malloc/memcpy to catch key material
        hookMemoryFunctions();
    }
}

// Alternative approach: Hook memory functions to catch potential keys
function hookMemoryFunctions() {
    console.log("[*] Hooking memory functions to catch potential crypto material...");
    
    const malloc = Module.findExportByName(null, "malloc");
    const memcpy = Module.findExportByName(null, "memcpy");
    
    if (malloc) {
        Interceptor.attach(malloc, {
            onEnter: function(args) {
                this.size = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (this.size >= 16 && this.size <= 64) {
                    console.log(`[MALLOC] Allocated ${this.size} bytes at ${retval} (potential crypto buffer)`);
                }
            }
        });
    }
    
    if (memcpy) {
        Interceptor.attach(memcpy, {
            onEnter: function(args) {
                const size = args[2].toInt32();
                if (size >= 16 && size <= 64) {
                    dumpMemory(args[1], size, "MEMCPY_SRC");
                }
            }
        });
    }
}

// Start the hooking process
setTimeout(hookAESFunctions, 1000);

console.log("[*] Frida AES Hook Script loaded. Waiting for libgojni...");