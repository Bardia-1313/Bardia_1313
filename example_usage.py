#!/usr/bin/env python3
"""
Example Python script to demonstrate how to use the AES Hook Frida script
نمونه اسکریپت پایتون برای نشان دادن نحوه استفاده از اسکریپت فریدا AES Hook
"""

import frida
import sys
import time
import json

class AESHookExample:
    def __init__(self, device_id=None, target_package=None):
        self.device_id = device_id
        self.target_package = target_package
        self.session = None
        self.script = None
        
    def on_message(self, message, data):
        """Handle messages from the Frida script"""
        if message['type'] == 'send':
            print(f"[SCRIPT] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[ERROR] {message['stack']}")
    
    def load_script(self, script_path="aes_hook_frida.js"):
        """Load the AES hook script"""
        try:
            with open(script_path, 'r') as f:
                script_source = f.read()
            
            self.script = self.session.create_script(script_source)
            self.script.on('message', self.on_message)
            self.script.load()
            print(f"[+] Script loaded successfully")
            return True
        except Exception as e:
            print(f"[-] Error loading script: {e}")
            return False
    
    def attach_to_process(self, process_name=None):
        """Attach to a running process"""
        try:
            if process_name:
                self.session = frida.get_usb_device().attach(process_name)
            else:
                # Get the first process that contains 'target' in name
                device = frida.get_usb_device()
                processes = device.enumerate_processes()
                
                target_process = None
                for process in processes:
                    if 'target' in process.name.lower() or 'app' in process.name.lower():
                        target_process = process
                        break
                
                if target_process:
                    self.session = device.attach(target_process.pid)
                    print(f"[+] Attached to process: {target_process.name} (PID: {target_process.pid})")
                else:
                    print("[-] No suitable target process found")
                    return False
            
            return True
        except Exception as e:
            print(f"[-] Error attaching to process: {e}")
            return False
    
    def spawn_and_attach(self, package_name):
        """Spawn a new process and attach to it"""
        try:
            device = frida.get_usb_device()
            pid = device.spawn([package_name])
            self.session = device.attach(pid)
            device.resume(pid)
            print(f"[+] Spawned and attached to: {package_name} (PID: {pid})")
            return True
        except Exception as e:
            print(f"[-] Error spawning process: {e}")
            return False
    
    def get_extracted_data(self):
        """Get extracted keys and IVs from the script"""
        try:
            # Access the global object from the script
            result = self.script.exports.get_extracted_keys()
            keys = result if result else []
            
            result = self.script.exports.get_extracted_ivs()
            ivs = result if result else []
            
            return {
                'keys': keys,
                'ivs': ivs,
                'hook_count': self.script.exports.get_hook_count()
            }
        except Exception as e:
            print(f"[-] Error getting extracted data: {e}")
            return None
    
    def run_interactive(self):
        """Run in interactive mode"""
        print("[+] Starting interactive mode...")
        print("[+] Commands:")
        print("  'keys' - Show extracted keys")
        print("  'ivs' - Show extracted IVs")
        print("  'scan' - Trigger memory scan")
        print("  'stats' - Show statistics")
        print("  'quit' - Exit")
        
        try:
            while True:
                command = input("\n[frida] > ").strip().lower()
                
                if command == 'quit':
                    break
                elif command == 'keys':
                    data = self.get_extracted_data()
                    if data and data['keys']:
                        print("\n[EXTRACTED KEYS]:")
                        for i, key in enumerate(data['keys'], 1):
                            print(f"  {i}. {key}")
                    else:
                        print("[!] No keys extracted yet")
                
                elif command == 'ivs':
                    data = self.get_extracted_data()
                    if data and data['ivs']:
                        print("\n[EXTRACTED IVS]:")
                        for i, iv in enumerate(data['ivs'], 1):
                            print(f"  {i}. {iv}")
                    else:
                        print("[!] No IVs extracted yet")
                
                elif command == 'scan':
                    print("[+] Triggering memory scan...")
                    self.script.exports.scan_for_keys()
                
                elif command == 'stats':
                    data = self.get_extracted_data()
                    if data:
                        print(f"\n[STATISTICS]:")
                        print(f"  Total hooks: {data['hook_count']}")
                        print(f"  Unique keys: {len(data['keys'])}")
                        print(f"  Unique IVs: {len(data['ivs'])}")
                    else:
                        print("[!] Could not get statistics")
                
                else:
                    print("[!] Unknown command")
                    
        except KeyboardInterrupt:
            print("\n[+] Exiting...")
    
    def save_results(self, filename="aes_results.json"):
        """Save extracted results to a JSON file"""
        try:
            data = self.get_extracted_data()
            if data:
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"[+] Results saved to {filename}")
            else:
                print("[-] No data to save")
        except Exception as e:
            print(f"[-] Error saving results: {e}")

def main():
    """Main function with example usage"""
    print("=== AES Hook Frida Script Example ===")
    print("نمونه استفاده از اسکریپت فریدا AES Hook")
    
    # Example 1: Attach to running process
    print("\n[EXAMPLE 1] Attaching to running process...")
    hook_example = AESHookExample()
    
    if hook_example.attach_to_process():
        if hook_example.load_script():
            print("[+] Successfully attached and loaded script")
            
            # Wait for some activity
            print("[+] Waiting for AES operations... (press Ctrl+C to stop)")
            try:
                time.sleep(30)  # Wait 30 seconds
                
                # Get results
                results = hook_example.get_extracted_data()
                if results:
                    print(f"\n[RESULTS]:")
                    print(f"  Hooks: {results['hook_count']}")
                    print(f"  Keys: {len(results['keys'])}")
                    print(f"  IVs: {len(results['ivs'])}")
                    
                    # Save results
                    hook_example.save_results()
                
            except KeyboardInterrupt:
                print("\n[+] Stopping...")
    
    # Example 2: Spawn and attach
    print("\n[EXAMPLE 2] Spawning new process...")
    target_package = "com.example.encryptionapp"  # Replace with your target
    
    hook_example2 = AESHookExample()
    if hook_example2.spawn_and_attach(target_package):
        if hook_example2.load_script():
            print("[+] Successfully spawned and loaded script")
            
            # Run interactive mode
            hook_example2.run_interactive()
    
    print("\n[+] Example completed")

if __name__ == "__main__":
    main()