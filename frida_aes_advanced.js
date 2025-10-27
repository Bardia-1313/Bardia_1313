console.log("[*] Advanced AES Hook Script for libgojni");

// Global variables for tracking
let keyDatabase = new Map();
let callStack = [];
let hookedFunctions = new Set();

// Enhanced byte conversion with ASCII display
function bytesToHex(bytes, length) {
    if (!bytes || length <= 0) return "";
    
    let hex = "";
    let ascii = "";
    
    for (let i = 0; i < length; i++) {
        try {
            const byte = Memory.readU8(bytes.add(i));
            hex += byte.toString(16).padStart(2, '0') + " ";
            ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : ".";
            
            if ((i + 1) % 16 === 0) {
                hex += "\n";
                ascii += "\n";
            }
        } catch (e) {
            hex += "?? ";
            ascii += "?";
        }
    }
    
    return {
        hex: hex.trim(),
        ascii: ascii,
        raw: hex.replace(/\s/g, "")
    };
}

// Enhanced memory dumping with better formatting
function dumpMemory(ptr, size, label) {
    if (!ptr || size <= 0) return;
    
    const data = bytesToHex(ptr, Math.min(size, 256));
    console.log("\n╔══ " + label + " ══╗");
    console.log("║ Address: " + ptr);
    console.log("║ Size: " + size + " bytes");
    console.log("║ HEX:");
    console.log(data.hex.split('\n').map(line => "║ " + line).join('\n'));
    console.log("║ ASCII: " + data.ascii.replace(/\n/g, '\n║        '));
    console.log("╚" + "═".repeat(Math.max(30, label.length + 8)) + "╝\n");
    
    return data.raw;
}

// Save key to database
function saveKey(key, keyLength, context) {
    const keyHex = bytesToHex(key, keyLength).raw;
    if (keyHex && keyHex.length > 0) {
        keyDatabase.set(keyHex, {
            length: keyLength,
            context: context,
            timestamp: new Date().toISOString(),
            usageCount: (keyDatabase.get(keyHex)?.usageCount || 0) + 1
        });
        console.log("[KEY] Saved key: " + keyHex.substring(0, 32) + "... (length: " + keyLength + ")");
    }
}

// Print key database
function printKeyDatabase() {
    console.log("\n╔══ KEY DATABASE ══╗");
    if (keyDatabase.size === 0) {
        console.log("║ No keys captured");
    } else {
        keyDatabase.forEach((info, key) => {
            console.log("║ Key: " + key.substring(0, 32) + "...");
            console.log("║ Length: " + info.length + " bytes");
            console.log("║ Context: " + info.context);
            console.log("║ Usage: " + info.usageCount + " times");
            console.log("║ First seen: " + info.timestamp);
            console.log("║ " + "─".repeat(50));
        });
    }
    console.log("╚" + "═".repeat(20) + "╝\n");
}

// Get stack trace
function getStackTrace() {
    try {
        return Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .slice(0, 10)
            .map(symbol => "  " + symbol.toString())
            .join('\n');
    } catch (e) {
        return "  [Stack trace unavailable]";
    }
}

// Wait for library with timeout
function waitForLibrary(timeout = 30000) {
    return new Promise((resolve, reject) => {
        const startTime = Date.now();
        const checkLibrary = () => {
            try {
                const lib = Process.findModuleByName("libgojni.so");
                if (lib) {
                    console.log("[+] Found libgojni.so at: " + lib.base);
                    console.log("[+] Library size: " + lib.size + " bytes");
                    console.log("[+] Library path: " + lib.path);
                    resolve(lib);
                } else if (Date.now() - startTime > timeout) {
                    reject(new Error("Timeout waiting for libgojni.so"));
                } else {
                    setTimeout(checkLibrary, 100);
                }
            } catch (e) {
                if (Date.now() - startTime > timeout) {
                    reject(e);
                } else {
                    setTimeout(checkLibrary, 100);
                }
            }
        };
        checkLibrary();
    });
}

// Hook AES functions with enhanced logging
function hookAdvancedAES(lib) {
    console.log("[*] Installing advanced AES hooks...");
    
    // OpenSSL AES functions
    const opensslFunctions = [
        { name: "AES_set_encrypt_key", args: ["key", "bits", "aes_key"] },
        { name: "AES_set_decrypt_key", args: ["key", "bits", "aes_key"] },
        { name: "AES_encrypt", args: ["in", "out", "aes_key"] },
        { name: "AES_decrypt", args: ["in", "out", "aes_key"] },
        { name: "AES_cbc_encrypt", args: ["in", "out", "length", "aes_key", "iv", "enc"] }
    ];
    
    opensslFunctions.forEach(func => {
        const funcPtr = Module.findExportByName("libgojni.so", func.name);
        if (funcPtr && !hookedFunctions.has(func.name)) {
            hookOpenSSLFunction(func.name, funcPtr, func.args);
            hookedFunctions.add(func.name);
        }
    });
    
    // Search for mangled C++ functions
    const symbols = lib.enumerateSymbols();
    symbols.forEach(symbol => {
        if (symbol.name.includes("AES") || symbol.name.includes("aes")) {
            if (symbol.type === "function" && !hookedFunctions.has(symbol.name)) {
                console.log("[+] Found AES symbol: " + symbol.name);
                hookGenericFunction(symbol.name, symbol.address);
                hookedFunctions.add(symbol.name);
            }
        }
    });
    
    // Hook EVP functions
    hookEVPFunctions();
}

// Hook OpenSSL specific functions
function hookOpenSSLFunction(funcName, funcPtr, argNames) {
    try {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                console.log("\n🔐 [OPENSSL] " + funcName + " called");
                console.log("Thread: " + Process.getCurrentThreadId());
                console.log("Timestamp: " + new Date().toISOString());
                
                this.funcName = funcName;
                this.args = {};
                
                // Parse arguments based on function
                if (funcName.includes("set_encrypt_key") || funcName.includes("set_decrypt_key")) {
                    const keyBits = args[1].toInt32();
                    const keyBytes = keyBits / 8;
                    this.keyData = dumpMemory(args[0], keyBytes, "AES Key (" + keyBits + " bits)");
                    this.keyBits = keyBits;
                    this.args.key = args[0];
                    this.args.aes_key = args[2];
                    
                    saveKey(args[0], keyBytes, funcName);
                    
                } else if (funcName.includes("encrypt") || funcName.includes("decrypt")) {
                    this.args.input = args[0];
                    this.args.output = args[1];
                    this.args.aes_key = args[2];
                    
                    if (funcName === "AES_cbc_encrypt") {
                        this.args.length = args[2];
                        this.args.aes_key = args[3];
                        this.args.iv = args[4];
                        this.args.enc = args[5];
                        
                        const length = args[2].toInt32();
                        dumpMemory(args[0], Math.min(length, 64), "Input Data");
                        dumpMemory(args[4], 16, "IV");
                        console.log("Length: " + length + " bytes");
                        console.log("Encrypt mode: " + (args[5].toInt32() ? "encrypt" : "decrypt"));
                    } else {
                        dumpMemory(args[0], 16, "Input Block");
                    }
                }
                
                // Get stack trace
                console.log("Stack trace:");
                console.log(getStackTrace.call(this));
            },
            
            onLeave: function(retval) {
                console.log("[OPENSSL] " + this.funcName + " returned: " + retval);
                
                if (this.funcName.includes("encrypt") || this.funcName.includes("decrypt")) {
                    if (this.funcName === "AES_cbc_encrypt" && this.args.length) {
                        const length = this.args.length.toInt32();
                        dumpMemory(this.args.output, Math.min(length, 64), "Output Data");
                    } else if (this.args.output) {
                        dumpMemory(this.args.output, 16, "Output Block");
                    }
                }
                
                console.log("🔐 [OPENSSL] " + this.funcName + " finished\n");
            }
        });
        
        console.log("[+] Hooked OpenSSL function: " + funcName);
    } catch (e) {
        console.log("[-] Failed to hook " + funcName + ": " + e.message);
    }
}

// Hook EVP functions
function hookEVPFunctions() {
    const evpFunctions = [
        "EVP_CIPHER_CTX_new",
        "EVP_CIPHER_CTX_free",
        "EVP_EncryptInit_ex",
        "EVP_DecryptInit_ex",
        "EVP_EncryptUpdate",
        "EVP_DecryptUpdate",
        "EVP_EncryptFinal_ex",
        "EVP_DecryptFinal_ex"
    ];
    
    evpFunctions.forEach(funcName => {
        const funcPtr = Module.findExportByName("libgojni.so", funcName);
        if (funcPtr && !hookedFunctions.has(funcName)) {
            hookEVPFunction(funcName, funcPtr);
            hookedFunctions.add(funcName);
        }
    });
}

// Hook EVP specific functions
function hookEVPFunction(funcName, funcPtr) {
    try {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                console.log("\n🔑 [EVP] " + funcName + " called");
                
                this.funcName = funcName;
                this.args = args;
                
                if (funcName.includes("Init")) {
                    if (args[2]) dumpMemory(args[2], 32, "Key");
                    if (args[3]) dumpMemory(args[3], 16, "IV");
                    
                    // Save key if present
                    if (args[2]) {
                        saveKey(args[2], 32, funcName); // Assume 256-bit key
                    }
                    
                } else if (funcName.includes("Update")) {
                    const inLen = args[2].toInt32();
                    if (args[1]) dumpMemory(args[1], Math.min(inLen, 64), "Input Data");
                    console.log("Input length: " + inLen);
                }
            },
            
            onLeave: function(retval) {
                console.log("[EVP] " + this.funcName + " returned: " + retval);
                
                if (this.funcName.includes("Update") && this.args[3]) {
                    const outLen = Memory.readU32(this.args[4]);
                    if (outLen > 0) {
                        dumpMemory(this.args[3], Math.min(outLen, 64), "Output Data");
                        console.log("Output length: " + outLen);
                    }
                }
                
                console.log("🔑 [EVP] " + this.funcName + " finished\n");
            }
        });
        
        console.log("[+] Hooked EVP function: " + funcName);
    } catch (e) {
        console.log("[-] Failed to hook EVP function " + funcName + ": " + e.message);
    }
}

// Generic function hooking with pattern analysis
function hookGenericFunction(funcName, funcPtr) {
    if (hookedFunctions.has(funcName)) return;
    
    try {
        Interceptor.attach(funcPtr, {
            onEnter: function(args) {
                console.log("\n🔍 [GENERIC] " + funcName);
                
                this.funcName = funcName;
                
                // Analyze arguments for potential crypto data
                for (let i = 0; i < 6; i++) {
                    if (args[i] && !args[i].isNull()) {
                        try {
                            // Check if this looks like crypto data
                            const sample = Memory.readByteArray(args[i], 16);
                            if (sample) {
                                console.log("Arg[" + i + "]: " + args[i] + " (16 bytes): " + 
                                          Array.from(new Uint8Array(sample))
                                               .map(b => b.toString(16).padStart(2, '0'))
                                               .join(' '));
                            }
                        } catch (e) {
                            console.log("Arg[" + i + "]: " + args[i] + " (not memory)");
                        }
                    }
                }
            },
            
            onLeave: function(retval) {
                // Silent exit for generic functions
            }
        });
        
        hookedFunctions.add(funcName);
    } catch (e) {
        console.log("[-] Failed to hook generic function " + funcName);
    }
}

// Monitor memory writes for key detection
function hookMemoryWrites() {
    console.log("[*] Setting up memory write monitoring...");
    
    // Hook memcpy for potential key copying
    const memcpy = Module.findExportByName(null, "memcpy");
    if (memcpy) {
        Interceptor.attach(memcpy, {
            onEnter: function(args) {
                const size = args[2].toInt32();
                if (size >= 16 && size <= 64) { // Potential key sizes
                    this.isKeyOperation = true;
                    this.src = args[1];
                    this.dst = args[0];
                    this.size = size;
                }
            },
            onLeave: function(retval) {
                if (this.isKeyOperation) {
                    console.log("[MEMCPY] Potential key copy: " + this.size + " bytes");
                    const keyData = dumpMemory(this.src, this.size, "Copied Key Data");
                    saveKey(this.src, this.size, "memcpy");
                }
            }
        });
    }
}

// Setup periodic reporting
function setupReporting() {
    setInterval(() => {
        if (keyDatabase.size > 0) {
            console.log("\n📊 [REPORT] Found " + keyDatabase.size + " unique keys");
            console.log("📊 [REPORT] Hooked " + hookedFunctions.size + " functions");
        }
    }, 30000); // Report every 30 seconds
}

// Main execution with error handling
async function main() {
    try {
        console.log("[*] Advanced AES Hook Script Starting...");
        console.log("[*] Waiting for libgojni.so...");
        
        const lib = await waitForLibrary(60000); // 60 second timeout
        
        console.log("[+] Library loaded, installing hooks...");
        
        // Install all hooks
        hookAdvancedAES(lib);
        hookMemoryWrites();
        setupReporting();
        
        console.log("[+] All hooks installed!");
        console.log("[*] Monitoring AES operations... (Press Ctrl+C to view key database)");
        
        // Setup cleanup on exit
        Process.setExceptionHandler((exception) => {
            console.log("\n[!] Exception: " + exception.message);
            printKeyDatabase();
            return false;
        });
        
    } catch (error) {
        console.log("[-] Error: " + error.message);
        console.log("[-] Failed to initialize hooks");
    }
}

// Handle script termination
Java.perform(() => {
    console.log("[*] Java runtime available");
});

// Add command to print key database
globalThis.printKeys = printKeyDatabase;
globalThis.hookedCount = () => hookedFunctions.size;

// Start the main script
main();