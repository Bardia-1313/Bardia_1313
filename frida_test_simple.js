// اسکریپت ساده برای تست وجود libgojni و توابع AES
console.log("[*] Simple libgojni AES Detection Script");

function testLibraryPresence() {
    // بررسی وجود libgojni
    const lib = Process.findModuleByName("libgojni.so");
    if (!lib) {
        console.log("[-] libgojni.so not found!");
        console.log("[*] Available libraries:");
        Process.enumerateModules().forEach(module => {
            if (module.name.includes("go") || module.name.includes("jni")) {
                console.log("  - " + module.name + " at " + module.base);
            }
        });
        return false;
    }
    
    console.log("[+] Found libgojni.so at: " + lib.base);
    console.log("[+] Size: " + lib.size + " bytes");
    console.log("[+] Path: " + lib.path);
    
    return lib;
}

function findAESFunctions(lib) {
    const aesFunctions = [
        "AES_set_encrypt_key",
        "AES_set_decrypt_key", 
        "AES_encrypt",
        "AES_decrypt",
        "AES_cbc_encrypt"
    ];
    
    console.log("\n[*] Searching for AES functions...");
    
    let foundFunctions = 0;
    
    // جستجوی توابع صریح
    aesFunctions.forEach(funcName => {
        const funcPtr = Module.findExportByName("libgojni.so", funcName);
        if (funcPtr) {
            console.log("[+] Found: " + funcName + " at " + funcPtr);
            foundFunctions++;
        }
    });
    
    // جستجوی در symbol table
    console.log("\n[*] Searching symbols containing 'aes' or 'AES'...");
    const symbols = lib.enumerateSymbols();
    const aesSymbols = symbols.filter(symbol => 
        symbol.name.toLowerCase().includes("aes") && symbol.type === "function"
    );
    
    if (aesSymbols.length > 0) {
        console.log("[+] Found " + aesSymbols.length + " AES-related symbols:");
        aesSymbols.slice(0, 10).forEach(symbol => {
            console.log("  - " + symbol.name + " at " + symbol.address);
        });
        if (aesSymbols.length > 10) {
            console.log("  ... and " + (aesSymbols.length - 10) + " more");
        }
    }
    
    // جستجوی در exports
    console.log("\n[*] Searching exports containing 'crypt' or 'cipher'...");
    const exports = lib.enumerateExports();
    const cryptExports = exports.filter(exp => 
        exp.name.toLowerCase().includes("crypt") || 
        exp.name.toLowerCase().includes("cipher") ||
        exp.name.toLowerCase().includes("crypto")
    );
    
    if (cryptExports.length > 0) {
        console.log("[+] Found " + cryptExports.length + " crypto-related exports:");
        cryptExports.slice(0, 10).forEach(exp => {
            console.log("  - " + exp.name + " at " + exp.address);
        });
        if (cryptExports.length > 10) {
            console.log("  ... and " + (cryptExports.length - 10) + " more");
        }
    }
    
    return foundFunctions;
}

function findGoFunctions(lib) {
    console.log("\n[*] Searching for Go crypto functions...");
    
    const goFunctions = [
        "crypto/aes",
        "crypto/cipher", 
        "crypto/rand",
        "golang.org/x/crypto"
    ];
    
    const symbols = lib.enumerateSymbols();
    let foundGo = 0;
    
    goFunctions.forEach(pattern => {
        const matches = symbols.filter(symbol => symbol.name.includes(pattern));
        if (matches.length > 0) {
            console.log("[+] Found " + matches.length + " symbols matching '" + pattern + "':");
            matches.slice(0, 5).forEach(symbol => {
                console.log("  - " + symbol.name);
            });
            if (matches.length > 5) {
                console.log("  ... and " + (matches.length - 5) + " more");
            }
            foundGo += matches.length;
        }
    });
    
    return foundGo;
}

// اجرای اصلی
console.log("[*] Starting detection...");

const lib = testLibraryPresence();
if (lib) {
    const aesCount = findAESFunctions(lib);
    const goCount = findGoFunctions(lib);
    
    console.log("\n" + "=".repeat(50));
    console.log("SUMMARY:");
    console.log("  AES functions found: " + aesCount);
    console.log("  Go crypto symbols found: " + goCount);
    
    if (aesCount > 0 || goCount > 0) {
        console.log("\n[+] Library appears to contain crypto functions!");
        console.log("[*] You can now use the main hook scripts:");
        console.log("    frida -U -p [PID] -l frida_aes_hook.js");
        console.log("    frida -U -p [PID] -l frida_aes_advanced.js");
    } else {
        console.log("\n[-] No obvious AES/crypto functions found");
        console.log("[*] The library might use:");
        console.log("    - Obfuscated function names");
        console.log("    - Static linking");
        console.log("    - Custom crypto implementation");
    }
} else {
    console.log("\n[-] libgojni.so not found in current process");
    console.log("[*] Make sure:");
    console.log("    - The app is running");
    console.log("    - The library name is correct");
    console.log("    - The library is loaded");
}

console.log("\n[*] Detection complete!");