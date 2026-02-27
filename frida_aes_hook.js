console.log("[*] Starting AES Hook Script for libgojni");

// Function to convert byte array to hex string
function bytesToHex(bytes, length) {
    if (!bytes || length <= 0) return "";
    
    var result = "";
    for (var i = 0; i < length; i++) {
        var byte = Memory.readU8(bytes.add(i));
        result += byte.toString(16).padStart(2, '0');
    }
    return result;
}

// Function to dump memory
function dumpMemory(ptr, size, label) {
    if (!ptr || size <= 0) return;
    
    console.log("=== " + label + " ===");
    console.log("Address: " + ptr);
    console.log("Size: " + size + " bytes");
    console.log("Hex: " + bytesToHex(ptr, Math.min(size, 256))); // Limit to 256 bytes for readability
    console.log("==================");
}

// Wait for libgojni to be loaded
function waitForLibrary() {
    return new Promise((resolve) => {
        const checkLibrary = () => {
            try {
                const lib = Process.findModuleByName("libgojni.so");
                if (lib) {
                    console.log("[+] Found libgojni.so at: " + lib.base);
                    resolve(lib);
                } else {
                    setTimeout(checkLibrary, 100);
                }
            } catch (e) {
                setTimeout(checkLibrary, 100);
            }
        };
        checkLibrary();
    });
}

// Hook AES functions
function hookAESFunctions(lib) {
    console.log("[*] Starting to hook AES functions in libgojni");
    
    // Common AES function names to hook
    const aesFunctions = [
        "AES_set_encrypt_key",
        "AES_set_decrypt_key", 
        "AES_encrypt",
        "AES_decrypt",
        "AES_cbc_encrypt",
        "AES_cfb128_encrypt",
        "AES_ofb128_encrypt",
        "AES_ecb_encrypt",
        "AES_ige_encrypt",
        "EVP_aes_128_cbc",
        "EVP_aes_192_cbc", 
        "EVP_aes_256_cbc",
        "EVP_aes_128_ecb",
        "EVP_aes_192_ecb",
        "EVP_aes_256_ecb",
        "EVP_aes_128_cfb128",
        "EVP_aes_192_cfb128",
        "EVP_aes_256_cfb128",
        "EVP_aes_128_ofb",
        "EVP_aes_192_ofb",
        "EVP_aes_256_ofb",
        "EVP_aes_128_gcm",
        "EVP_aes_192_gcm",
        "EVP_aes_256_gcm"
    ];
    
    // Try to find and hook each function
    aesFunctions.forEach(funcName => {
        try {
            const funcPtr = Module.findExportByName("libgojni.so", funcName);
            if (funcPtr) {
                console.log("[+] Found " + funcName + " at: " + funcPtr);
                hookFunction(funcName, funcPtr);
            } else {
                // Try to find by pattern in the library
                const symbols = lib.enumerateSymbols();
                symbols.forEach(symbol => {
                    if (symbol.name.includes(funcName) || symbol.name.toLowerCase().includes("aes")) {
                        console.log("[+] Found potential AES symbol: " + symbol.name + " at: " + symbol.address);
                        hookFunction(symbol.name, symbol.address);
                    }
                });
            }
        } catch (e) {
            console.log("[-] Error finding " + funcName + ": " + e.message);
        }
    });
    
    // Hook any function with "aes" in the name
    try {
        const symbols = lib.enumerateSymbols();
        symbols.forEach(symbol => {
            if (symbol.name.toLowerCase().includes("aes") && symbol.type === "function") {
                console.log("[+] Found AES-related function: " + symbol.name + " at: " + symbol.address);
                hookGenericAESFunction(symbol.name, symbol.address);
            }
        });
    } catch (e) {
        console.log("[-] Error enumerating symbols: " + e.message);
    }
}

// Generic function hooking for AES operations
function hookFunction(funcName, funcPtr) {
    try {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                console.log("\n[*] === " + funcName + " CALLED ===");
                console.log("Thread: " + Process.getCurrentThreadId());
                console.log("Timestamp: " + new Date().toISOString());
                
                // Log arguments based on function type
                if (funcName.includes("set_encrypt_key") || funcName.includes("set_decrypt_key")) {
                    console.log("Key: " + bytesToHex(args[0], 32)); // Assume max 256-bit key
                    console.log("Key length: " + args[1]);
                    this.keySchedule = args[2];
                } else if (funcName.includes("encrypt") || funcName.includes("decrypt")) {
                    dumpMemory(args[0], 16, "Input Data (16 bytes)");
                    dumpMemory(args[1], 16, "Output Buffer");
                    if (args[2]) {
                        dumpMemory(args[2], 240, "Key Schedule"); // AES key schedule is typically 240 bytes for AES-256
                    }
                }
                
                // Store context for onLeave
                this.funcName = funcName;
                this.args = [];
                for (let i = 0; i < 8; i++) {
                    this.args[i] = args[i];
                }
            },
            onLeave: function(retval) {
                console.log("[*] " + this.funcName + " returned: " + retval);
                
                // Dump output for encrypt/decrypt functions
                if ((this.funcName.includes("encrypt") || this.funcName.includes("decrypt")) && this.args[1]) {
                    dumpMemory(this.args[1], 16, "Output Data (16 bytes)");
                }
                
                console.log("[*] === " + this.funcName + " FINISHED ===\n");
            }
        });
        
        console.log("[+] Successfully hooked: " + funcName);
    } catch (e) {
        console.log("[-] Failed to hook " + funcName + ": " + e.message);
    }
}

// Generic AES function hooking
function hookGenericAESFunction(funcName, funcPtr) {
    try {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                console.log("\n[*] === GENERIC AES FUNCTION: " + funcName + " ===");
                console.log("Thread: " + Process.getCurrentThreadId());
                
                // Log first few arguments as hex
                for (let i = 0; i < Math.min(4, arguments.length); i++) {
                    if (args[i] && !args[i].isNull()) {
                        try {
                            // Try to read as pointer to data
                            console.log("Arg[" + i + "]: " + args[i] + " -> " + bytesToHex(args[i], 32));
                        } catch (e) {
                            console.log("Arg[" + i + "]: " + args[i] + " (not readable as memory)");
                        }
                    } else {
                        console.log("Arg[" + i + "]: " + args[i]);
                    }
                }
                
                this.funcName = funcName;
            },
            onLeave: function(retval) {
                console.log("[*] " + this.funcName + " returned: " + retval);
                console.log("[*] === END GENERIC AES FUNCTION ===\n");
            }
        });
        
        console.log("[+] Successfully hooked generic AES function: " + funcName);
    } catch (e) {
        console.log("[-] Failed to hook generic AES function " + funcName + ": " + e.message);
    }
}

// Hook Go crypto functions that might be present
function hookGoCryptoFunctions() {
    console.log("[*] Looking for Go crypto functions...");
    
    const goCryptoFunctions = [
        "crypto/aes.(*aesCipher).Encrypt",
        "crypto/aes.(*aesCipher).Decrypt", 
        "crypto/aes.NewCipher",
        "crypto/cipher.NewCBCEncrypter",
        "crypto/cipher.NewCBCDecrypter",
        "crypto/cipher.NewGCM"
    ];
    
    goCryptoFunctions.forEach(funcName => {
        try {
            const funcPtr = Module.findExportByName("libgojni.so", funcName);
            if (funcPtr) {
                console.log("[+] Found Go crypto function: " + funcName);
                hookGenericAESFunction(funcName, funcPtr);
            }
        } catch (e) {
            // Continue silently
        }
    });
}

// Hook memory allocation functions to catch key material
function hookMemoryFunctions() {
    console.log("[*] Hooking memory allocation functions...");
    
    const malloc = Module.findExportByName(null, "malloc");
    const calloc = Module.findExportByName(null, "calloc");
    
    if (malloc) {
        Interceptor.attach(malloc, {
            onEnter: function(args) {
                this.size = args[0].toInt32();
            },
            onLeave: function(retval) {
                if (this.size >= 16 && this.size <= 64) { // Potential key sizes
                    console.log("[*] malloc(" + this.size + ") = " + retval + " (potential key allocation)");
                }
            }
        });
    }
    
    if (calloc) {
        Interceptor.attach(calloc, {
            onEnter: function(args) {
                this.size = args[0].toInt32() * args[1].toInt32();
            },
            onLeave: function(retval) {
                if (this.size >= 16 && this.size <= 64) { // Potential key sizes
                    console.log("[*] calloc() = " + retval + " size: " + this.size + " (potential key allocation)");
                }
            }
        });
    }
}

// Main execution
console.log("[*] AES Hook Script Loaded");
console.log("[*] Waiting for libgojni.so to be loaded...");

waitForLibrary().then(lib => {
    console.log("[+] libgojni.so loaded, starting hooks...");
    
    // Hook standard AES functions
    hookAESFunctions(lib);
    
    // Hook Go crypto functions
    hookGoCryptoFunctions();
    
    // Hook memory allocation
    hookMemoryFunctions();
    
    console.log("[+] All hooks installed successfully!");
    console.log("[*] Monitoring AES operations...");
});

// Global exception handler
Process.setExceptionHandler(function(exception) {
    console.log("[!] Exception caught: " + exception.message);
    console.log("Context: " + JSON.stringify(exception.context, null, 2));
    return false; // Don't handle the exception, let it propagate
});