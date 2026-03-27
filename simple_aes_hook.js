/**
 * Simple AES Key/IV Extraction Script for libgojni
 * اسکریپت ساده برای استخراج کلید و IV از libgojni
 */

function hex(data) {
    return Array.from(new Uint8Array(data))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hookLib() {
    console.log("[*] Simple AES Hook - Looking for libgojni...");
    
    // Find target library
    let lib = null;
    const names = ["libgojni.so", "libgojni", "libgo.so"];
    
    for (let name of names) {
        try {
            lib = Process.getModuleByName(name);
            console.log(`[+] Found: ${name} at ${lib.base}`);
            break;
        } catch (e) {}
    }
    
    if (!lib) {
        console.log("[-] Library not found. Available modules:");
        Process.enumerateModules()
            .filter(m => m.name.toLowerCase().includes('go') || 
                        m.name.toLowerCase().includes('crypto') ||
                        m.name.toLowerCase().includes('jni'))
            .forEach(m => console.log(`  ${m.name}`));
        return;
    }
    
    // Hook key functions
    const patterns = ["aes", "crypto", "cipher", "encrypt", "decrypt"];
    let hooked = 0;
    
    lib.enumerateSymbols().forEach(sym => {
        const name = sym.name.toLowerCase();
        
        if (patterns.some(p => name.includes(p))) {
            try {
                console.log(`[+] Hooking: ${sym.name}`);
                
                Interceptor.attach(sym.address, {
                    onEnter: function(args) {
                        console.log(`\n[HOOK] ${sym.name}`);
                        
                        // Dump potential keys/IVs from arguments
                        for (let i = 0; i < Math.min(4, args.length); i++) {
                            if (!args[i] || args[i].isNull()) continue;
                            
                            try {
                                // Try 16, 24, 32 byte reads (AES key sizes)
                                [16, 24, 32].forEach(size => {
                                    try {
                                        const data = args[i].readByteArray(size);
                                        const hexData = hex(data);
                                        
                                        // Simple heuristic: look for non-zero data
                                        if (hexData !== '00'.repeat(size)) {
                                            console.log(`[KEY/IV] ARG${i} (${size}B): ${hexData}`);
                                        }
                                    } catch (e) {}
                                });
                            } catch (e) {}
                        }
                    }
                });
                hooked++;
            } catch (e) {}
        }
    });
    
    console.log(`[*] Hooked ${hooked} functions`);
    
    // Also hook common memory functions
    const malloc = Module.findExportByName(null, "malloc");
    const memcpy = Module.findExportByName(null, "memcpy");
    
    if (memcpy) {
        Interceptor.attach(memcpy, {
            onEnter: function(args) {
                const size = args[2].toInt32();
                if (size >= 16 && size <= 32) {
                    try {
                        const data = args[1].readByteArray(size);
                        const hexData = hex(data);
                        if (hexData !== '00'.repeat(size)) {
                            console.log(`[MEMCPY] ${size}B: ${hexData}`);
                        }
                    } catch (e) {}
                }
            }
        });
    }
}

setTimeout(hookLib, 1000);
console.log("[*] Simple AES Hook loaded...");