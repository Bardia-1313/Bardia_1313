/**
 * Specialized Frida Script for Go AES Functions in libgojni
 * Focuses on Go crypto/aes and crypto/cipher packages
 */

// Utility functions
function bytesToHex(bytes) {
    if (!bytes) return "null";
    let result = "";
    for (let i = 0; i < bytes.length; i++) {
        result += ("0" + bytes[i].toString(16)).slice(-2);
    }
    return result;
}

function dumpGoSlice(ptr, label) {
    if (!ptr || ptr.isNull()) {
        console.log(`[${label}] Null slice pointer`);
        return;
    }
    
    try {
        // Go slice structure: {ptr, len, cap}
        const dataPtr = ptr.readPointer();
        const length = ptr.add(Process.pointerSize).readUInt();
        const capacity = ptr.add(Process.pointerSize * 2).readUInt();
        
        console.log(`[${label}] Slice - Len: ${length}, Cap: ${capacity}, Ptr: ${dataPtr}`);
        
        if (dataPtr && !dataPtr.isNull() && length > 0 && length <= 64) {
            const data = dataPtr.readByteArray(length);
            console.log(`[${label}] Data: ${bytesToHex(new Uint8Array(data))}`);
        }
    } catch (e) {
        console.log(`[${label}] Error reading Go slice: ${e}`);
    }
}

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

function hookGoAESFunctions() {
    console.log("[*] Starting Go-specific AES function hooking...");
    
    // Find the target library
    let targetLib = null;
    const libNames = ["libgojni.so", "libgojni", "libgo.so"];
    
    for (let libName of libNames) {
        try {
            targetLib = Process.getModuleByName(libName);
            console.log(`[+] Found target library: ${libName} at ${targetLib.base}`);
            break;
        } catch (e) {
            continue;
        }
    }
    
    if (!targetLib) {
        console.log("[-] Target library not found. Scanning all modules...");
        Process.enumerateModules().forEach(module => {
            if (module.name.toLowerCase().includes("go") || 
                module.name.toLowerCase().includes("jni")) {
                console.log(`[?] Potential target: ${module.name} - ${module.base}`);
            }
        });
        return;
    }
    
    // Go crypto/aes function patterns
    const goAESPatterns = [
        // crypto/aes package functions
        "crypto/aes.NewCipher",
        "crypto/aes.(*aesCipher).Encrypt",
        "crypto/aes.(*aesCipher).Decrypt",
        "crypto/aes.(*aesCipherGCM).Seal",
        "crypto/aes.(*aesCipherGCM).Open",
        
        // crypto/cipher package functions
        "crypto/cipher.NewCBCEncrypter",
        "crypto/cipher.NewCBCDecrypter", 
        "crypto/cipher.NewCFBEncrypter",
        "crypto/cipher.NewCFBDecrypter",
        "crypto/cipher.NewOFB",
        "crypto/cipher.NewGCM",
        "crypto/cipher.(*cbc).CryptBlocks",
        "crypto/cipher.(*cfb).XORKeyStream",
        "crypto/cipher.(*ofb).XORKeyStream",
        "crypto/cipher.(*gcm).Seal",
        "crypto/cipher.(*gcm).Open",
        
        // Simplified patterns that might appear in stripped binaries
        "NewCipher",
        "CryptBlocks", 
        "XORKeyStream",
        "Seal",
        "Open"
    ];
    
    let hookedCount = 0;
    
    // Hook Go AES functions
    goAESPatterns.forEach(pattern => {
        try {
            const symbols = targetLib.enumerateSymbols().filter(symbol => 
                symbol.name.includes(pattern) || 
                symbol.name.toLowerCase().includes(pattern.toLowerCase().replace("/", "."))
            );
            
            symbols.forEach(symbol => {
                console.log(`[+] Hooking Go function: ${symbol.name} at ${symbol.address}`);
                
                Interceptor.attach(symbol.address, {
                    onEnter: function(args) {
                        console.log(`\n[GO_HOOK] ${symbol.name} called`);
                        console.log(`[INFO] Thread: ${this.threadId}`);
                        
                        // Store function name for onLeave
                        this.funcName = symbol.name;
                        
                        // Extract crypto data based on function type
                        if (symbol.name.includes("NewCipher")) {
                            // NewCipher(key []byte) (cipher.Block, error)
                            // args[0] should be the key slice
                            dumpGoSlice(args[0], "AES_KEY");
                        }
                        else if (symbol.name.includes("NewCBC") || symbol.name.includes("NewCFB") || symbol.name.includes("NewOFB")) {
                            // NewCBC*/NewCFB*/NewOFB*(block cipher.Block, iv []byte)
                            // args[1] should be the IV slice
                            dumpGoSlice(args[1], "CIPHER_IV");
                        }
                        else if (symbol.name.includes("NewGCM")) {
                            // NewGCM(cipher cipher.Block) (cipher.AEAD, error)
                            console.log("[GCM] GCM mode cipher created");
                        }
                        else if (symbol.name.includes("CryptBlocks")) {
                            // CryptBlocks(dst, src []byte)
                            dumpGoSlice(args[0], "CRYPT_DST");
                            dumpGoSlice(args[1], "CRYPT_SRC");
                        }
                        else if (symbol.name.includes("XORKeyStream")) {
                            // XORKeyStream(dst, src []byte)
                            dumpGoSlice(args[0], "XOR_DST");
                            dumpGoSlice(args[1], "XOR_SRC");
                        }
                        else if (symbol.name.includes("Seal")) {
                            // Seal(dst, nonce, plaintext, additionalData []byte) []byte
                            dumpGoSlice(args[1], "GCM_NONCE");
                            dumpGoSlice(args[2], "GCM_PLAINTEXT");
                            if (args[3] && !args[3].isNull()) {
                                dumpGoSlice(args[3], "GCM_AAD");
                            }
                        }
                        else if (symbol.name.includes("Open")) {
                            // Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
                            dumpGoSlice(args[1], "GCM_NONCE");
                            dumpGoSlice(args[2], "GCM_CIPHERTEXT");
                            if (args[3] && !args[3].isNull()) {
                                dumpGoSlice(args[3], "GCM_AAD");
                            }
                        }
                        
                        // Generic argument logging
                        for (let i = 0; i < Math.min(4, args.length); i++) {
                            console.log(`[ARG${i}] ${args[i]}`);
                        }
                    },
                    
                    onLeave: function(retval) {
                        console.log(`[RETURN] ${this.funcName} returned: ${retval}`);
                        
                        // For functions that return slices, try to dump the result
                        if (this.funcName.includes("Seal") && retval && !retval.isNull()) {
                            dumpGoSlice(retval, "SEAL_RESULT");
                        }
                        else if (this.funcName.includes("Open") && retval && !retval.isNull()) {
                            dumpGoSlice(retval, "OPEN_RESULT");
                        }
                    }
                });
                
                hookedCount++;
            });
        } catch (e) {
            // Function not found, continue
        }
    });
    
    // Also hook JNI functions that might be used to pass crypto data
    hookJNIFunctions(targetLib);
    
    console.log(`[*] Hooked ${hookedCount} Go AES functions`);
    
    if (hookedCount === 0) {
        console.log("[-] No Go AES functions found. Trying generic symbol scanning...");
        scanForCryptoSymbols(targetLib);
    }
}

function hookJNIFunctions(targetLib) {
    console.log("[*] Hooking JNI functions for crypto data transfer...");
    
    const jniFunctions = [
        "Java_", // Generic JNI function prefix
        "JNI_OnLoad",
        "GetByteArrayElements",
        "SetByteArrayRegion",
        "GetByteArrayRegion"
    ];
    
    jniFunctions.forEach(pattern => {
        try {
            const symbols = targetLib.enumerateSymbols().filter(symbol => 
                symbol.name.includes(pattern)
            );
            
            symbols.forEach(symbol => {
                if (symbol.name.includes("crypto") || 
                    symbol.name.includes("aes") || 
                    symbol.name.includes("cipher") ||
                    symbol.name.includes("encrypt") ||
                    symbol.name.includes("decrypt")) {
                    
                    console.log(`[+] Hooking JNI crypto function: ${symbol.name}`);
                    
                    Interceptor.attach(symbol.address, {
                        onEnter: function(args) {
                            console.log(`\n[JNI_HOOK] ${symbol.name} called`);
                            
                            // JNI functions typically have JNIEnv* as first argument
                            // Try to extract byte arrays from subsequent arguments
                            for (let i = 1; i < Math.min(6, args.length); i++) {
                                if (args[i] && !args[i].isNull()) {
                                    console.log(`[JNI_ARG${i}] ${args[i]}`);
                                    
                                    // Try to read as potential byte array
                                    try {
                                        dumpMemory(args[i], 32, `JNI_ARG${i}_DATA`);
                                    } catch (e) {
                                        // Not a direct pointer, might be JNI object
                                    }
                                }
                            }
                        }
                    });
                }
            });
        } catch (e) {
            // Continue on error
        }
    });
}

function scanForCryptoSymbols(targetLib) {
    console.log("[*] Scanning for any crypto-related symbols...");
    
    const cryptoKeywords = ["aes", "crypto", "cipher", "encrypt", "decrypt", "key", "iv"];
    let foundSymbols = [];
    
    try {
        targetLib.enumerateSymbols().forEach(symbol => {
            const name = symbol.name.toLowerCase();
            
            for (let keyword of cryptoKeywords) {
                if (name.includes(keyword)) {
                    foundSymbols.push(symbol);
                    break;
                }
            }
        });
        
        console.log(`[+] Found ${foundSymbols.length} crypto-related symbols:`);
        foundSymbols.forEach(symbol => {
            console.log(`    ${symbol.name} - ${symbol.address}`);
        });
        
        // Hook the most promising symbols
        foundSymbols.slice(0, 10).forEach(symbol => {
            try {
                console.log(`[+] Hooking discovered symbol: ${symbol.name}`);
                
                Interceptor.attach(symbol.address, {
                    onEnter: function(args) {
                        console.log(`\n[DISCOVERED] ${symbol.name} called`);
                        
                        // Basic argument analysis
                        for (let i = 0; i < Math.min(3, args.length); i++) {
                            if (args[i] && !args[i].isNull()) {
                                dumpMemory(args[i], 16, `${symbol.name}_ARG${i}`);
                            }
                        }
                    }
                });
            } catch (e) {
                // Hook failed, continue
            }
        });
        
    } catch (e) {
        console.log(`[-] Error during symbol scanning: ${e}`);
    }
}

// Start the Go-specific hooking
setTimeout(hookGoAESFunctions, 1000);

console.log("[*] Go AES Hook Script loaded. Targeting Go crypto functions...");