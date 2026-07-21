#!/usr/bin/env python3
"""
AES Hook Runner - Python script to run Frida AES hooking script
اسکریپت پایتون برای اجرای اسکریپت فریدا و مدیریت داده‌های استخراج شده AES
"""

import frida
import sys
import json
import time
import argparse
from datetime import datetime

class AESHookRunner:
    def __init__(self, device_id=None, package_name=None):
        self.device_id = device_id
        self.package_name = package_name
        self.session = None
        self.script = None
        self.extracted_data = []
        
    def on_message(self, message, data):
        """Handle messages from Frida script"""
        if message['type'] == 'send':
            print(f"[SCRIPT] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[ERROR] {message['stack']}")
            
    def load_script(self, script_path):
        """Load the Frida script from file"""
        try:
            with open(script_path, 'r') as f:
                script_source = f.read()
            return script_source
        except FileNotFoundError:
            print(f"[-] Script file not found: {script_path}")
            return None
        except Exception as e:
            print(f"[-] Error loading script: {e}")
            return None
            
    def attach_to_process(self, process_name):
        """Attach to a running process"""
        try:
            if self.device_id:
                device = frida.get_device(self.device_id)
            else:
                device = frida.get_usb_device()
                
            print(f"[+] Attaching to process: {process_name}")
            self.session = device.attach(process_name)
            return True
        except frida.ProcessNotFoundError:
            print(f"[-] Process '{process_name}' not found")
            return False
        except Exception as e:
            print(f"[-] Error attaching to process: {e}")
            return False
            
    def spawn_and_attach(self, package_name):
        """Spawn a new process and attach to it"""
        try:
            if self.device_id:
                device = frida.get_device(self.device_id)
            else:
                device = frida.get_usb_device()
                
            print(f"[+] Spawning process: {package_name}")
            pid = device.spawn([package_name])
            self.session = device.attach(pid)
            device.resume(pid)
            return True
        except Exception as e:
            print(f"[-] Error spawning process: {e}")
            return False
            
    def inject_script(self, script_source):
        """Inject the script into the target process"""
        try:
            print("[+] Injecting script...")
            self.script = self.session.create_script(script_source)
            self.script.on('message', self.on_message)
            self.script.load()
            print("[+] Script injected successfully")
            return True
        except Exception as e:
            print(f"[-] Error injecting script: {e}")
            return False
            
    def export_data(self):
        """Export extracted data from the script"""
        try:
            if self.script:
                # Call the export function in the script
                result = self.script.exports.exportaesdata()
                if result:
                    self.extracted_data.append(result)
                    return result
        except Exception as e:
            print(f"[-] Error exporting data: {e}")
        return None
        
    def save_data_to_file(self, filename=None):
        """Save extracted data to a JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aes_extracted_data_{timestamp}.json"
            
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.extracted_data, f, indent=2, ensure_ascii=False)
            print(f"[+] Data saved to: {filename}")
            return filename
        except Exception as e:
            print(f"[-] Error saving data: {e}")
            return None
            
    def run_interactive(self):
        """Run in interactive mode"""
        print("[+] Running in interactive mode. Commands:")
        print("  export - Export current data")
        print("  save [filename] - Save data to file")
        print("  quit - Exit")
        
        while True:
            try:
                command = input("frida> ").strip().split()
                if not command:
                    continue
                    
                if command[0] == "export":
                    data = self.export_data()
                    if data:
                        print(json.dumps(data, indent=2))
                        
                elif command[0] == "save":
                    filename = command[1] if len(command) > 1 else None
                    self.save_data_to_file(filename)
                    
                elif command[0] == "quit":
                    break
                    
                else:
                    print("Unknown command. Use: export, save [filename], or quit")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[-] Error: {e}")
                
    def run_automated(self, duration=60, export_interval=10):
        """Run in automated mode with periodic data export"""
        print(f"[+] Running in automated mode for {duration} seconds")
        print(f"[+] Exporting data every {export_interval} seconds")
        
        start_time = time.time()
        last_export = start_time
        
        try:
            while time.time() - start_time < duration:
                current_time = time.time()
                
                if current_time - last_export >= export_interval:
                    data = self.export_data()
                    if data:
                        print(f"[+] Exported data at {datetime.now()}")
                        print(f"    Total calls: {data.get('total_calls', 0)}")
                        print(f"    Unique keys: {data.get('unique_keys', 0)}")
                        print(f"    Unique IVs: {data.get('unique_ivs', 0)}")
                    
                    last_export = current_time
                    
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n[+] Stopping automated mode...")
            
        # Final export
        final_data = self.export_data()
        if final_data:
            self.save_data_to_file()
            
    def cleanup(self):
        """Clean up resources"""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()

def main():
    parser = argparse.ArgumentParser(description="AES Hook Runner - Frida script executor")
    parser.add_argument("-d", "--device", help="Device ID (optional)")
    parser.add_argument("-p", "--package", help="Package name to spawn")
    parser.add_argument("-n", "--name", help="Process name to attach to")
    parser.add_argument("-s", "--script", default="aes_hook_frida.js", help="Frida script path")
    parser.add_argument("-m", "--mode", choices=["interactive", "automated"], default="interactive", 
                       help="Run mode")
    parser.add_argument("-t", "--time", type=int, default=60, help="Duration for automated mode (seconds)")
    parser.add_argument("-i", "--interval", type=int, default=10, help="Export interval for automated mode (seconds)")
    
    args = parser.parse_args()
    
    if not args.package and not args.name:
        print("[-] Please specify either package name (-p) or process name (-n)")
        sys.exit(1)
        
    runner = AESHookRunner(args.device, args.package)
    
    try:
        # Load script
        script_source = runner.load_script(args.script)
        if not script_source:
            sys.exit(1)
            
        # Attach to process
        if args.package:
            success = runner.spawn_and_attach(args.package)
        else:
            success = runner.attach_to_process(args.name)
            
        if not success:
            sys.exit(1)
            
        # Inject script
        if not runner.inject_script(script_source):
            sys.exit(1)
            
        # Run in specified mode
        if args.mode == "interactive":
            runner.run_interactive()
        else:
            runner.run_automated(args.time, args.interval)
            
    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        runner.cleanup()

if __name__ == "__main__":
    main()