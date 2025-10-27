#!/usr/bin/env python3
"""
AES Data Analyzer - Analyze extracted AES data from Frida script
تحلیل‌گر داده‌های AES - تحلیل داده‌های استخراج شده از اسکریپت فریدا
"""

import json
import argparse
import base64
import binascii
from collections import defaultdict
from datetime import datetime

class AESDataAnalyzer:
    def __init__(self, data_file):
        self.data_file = data_file
        self.data = None
        self.load_data()
        
    def load_data(self):
        """Load data from JSON file"""
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            print(f"[+] Loaded data from {self.data_file}")
        except FileNotFoundError:
            print(f"[-] File not found: {self.data_file}")
            return False
        except json.JSONDecodeError as e:
            print(f"[-] Invalid JSON format: {e}")
            return False
        return True
        
    def analyze_function_calls(self):
        """Analyze function call patterns"""
        if not self.data:
            return
            
        print("\n=== Function Call Analysis ===")
        
        # Count function calls
        function_counts = defaultdict(int)
        for call in self.data.get('function_calls', []):
            function_counts[call['function']] += 1
            
        print("Function call frequencies:")
        for func, count in sorted(function_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {func}: {count} calls")
            
        # Analyze timing patterns
        timestamps = [call['timestamp'] for call in self.data.get('function_calls', [])]
        if timestamps:
            start_time = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
            duration = end_time - start_time
            print(f"\nAnalysis duration: {duration}")
            print(f"Average calls per second: {len(timestamps) / duration.total_seconds():.2f}")
            
    def analyze_keys(self):
        """Analyze extracted keys"""
        if not self.data:
            return
            
        print("\n=== Key Analysis ===")
        
        keys_hex = self.data.get('unique_keys_hex', [])
        keys_base64 = self.data.get('unique_keys_base64', [])
        
        print(f"Total unique keys found: {len(keys_hex)}")
        
        for i, (key_hex, key_b64) in enumerate(zip(keys_hex, keys_base64)):
            print(f"\nKey {i+1}:")
            print(f"  Hex: {key_hex}")
            print(f"  Base64: {key_b64}")
            print(f"  Length: {len(key_hex) // 2} bytes")
            
            # Analyze key entropy (simple check)
            try:
                key_bytes = binascii.unhexlify(key_hex)
                unique_bytes = len(set(key_bytes))
                entropy_ratio = unique_bytes / len(key_bytes)
                print(f"  Entropy ratio: {entropy_ratio:.2f}")
                
                if entropy_ratio < 0.5:
                    print("  ⚠️  Low entropy - possible weak key")
                elif entropy_ratio > 0.9:
                    print("  ✅ High entropy - good key")
                else:
                    print("  ⚠️  Medium entropy")
                    
            except Exception as e:
                print(f"  Error analyzing key: {e}")
                
    def analyze_ivs(self):
        """Analyze extracted IVs"""
        if not self.data:
            return
            
        print("\n=== IV Analysis ===")
        
        ivs_hex = self.data.get('unique_ivs_hex', [])
        ivs_base64 = self.data.get('unique_ivs_base64', [])
        
        print(f"Total unique IVs found: {len(ivs_hex)}")
        
        for i, (iv_hex, iv_b64) in enumerate(zip(ivs_hex, ivs_base64)):
            print(f"\nIV {i+1}:")
            print(f"  Hex: {iv_hex}")
            print(f"  Base64: {iv_b64}")
            print(f"  Length: {len(iv_hex) // 2} bytes")
            
            # Check for common IV patterns
            try:
                iv_bytes = binascii.unhexlify(iv_hex)
                
                # Check for zero IV
                if all(b == 0 for b in iv_bytes):
                    print("  ⚠️  Zero IV detected - security risk!")
                    
                # Check for sequential IV
                if len(iv_bytes) > 1:
                    sequential = True
                    for j in range(1, len(iv_bytes)):
                        if iv_bytes[j] != iv_bytes[j-1] + 1:
                            sequential = False
                            break
                    if sequential:
                        print("  ⚠️  Sequential IV detected - security risk!")
                        
                # Check entropy
                unique_bytes = len(set(iv_bytes))
                entropy_ratio = unique_bytes / len(iv_bytes)
                print(f"  Entropy ratio: {entropy_ratio:.2f}")
                
            except Exception as e:
                print(f"  Error analyzing IV: {e}")
                
    def analyze_data_patterns(self):
        """Analyze data patterns in function calls"""
        if not self.data:
            return
            
        print("\n=== Data Pattern Analysis ===")
        
        data_lengths = []
        data_previews = []
        
        for call in self.data.get('function_calls', []):
            if call.get('data_length', 0) > 0:
                data_lengths.append(call['data_length'])
                if call.get('data_preview'):
                    data_previews.append(call['data_preview'])
                    
        if data_lengths:
            print(f"Data length statistics:")
            print(f"  Total data blocks: {len(data_lengths)}")
            print(f"  Average length: {sum(data_lengths) / len(data_lengths):.2f} bytes")
            print(f"  Min length: {min(data_lengths)} bytes")
            print(f"  Max length: {max(data_lengths)} bytes")
            
            # Analyze common data patterns
            print(f"\nData preview analysis:")
            for i, preview in enumerate(data_previews[:5]):  # Show first 5
                print(f"  Preview {i+1}: {preview[:32]}...")
                
    def generate_report(self, output_file=None):
        """Generate comprehensive analysis report"""
        if not self.data:
            return
            
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"aes_analysis_report_{timestamp}.txt"
            
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("AES Data Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            # Summary
            f.write("SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total function calls: {self.data.get('total_calls', 0)}\n")
            f.write(f"Unique keys: {self.data.get('unique_keys', 0)}\n")
            f.write(f"Unique IVs: {self.data.get('unique_ivs', 0)}\n")
            f.write(f"Analysis timestamp: {self.data.get('timestamp', 'N/A')}\n\n")
            
            # Function calls
            f.write("FUNCTION CALLS\n")
            f.write("-" * 20 + "\n")
            function_counts = defaultdict(int)
            for call in self.data.get('function_calls', []):
                function_counts[call['function']] += 1
                
            for func, count in sorted(function_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{func}: {count} calls\n")
            f.write("\n")
            
            # Keys
            f.write("EXTRACTED KEYS\n")
            f.write("-" * 20 + "\n")
            for i, key_hex in enumerate(self.data.get('unique_keys_hex', [])):
                f.write(f"Key {i+1}: {key_hex}\n")
            f.write("\n")
            
            # IVs
            f.write("EXTRACTED IVS\n")
            f.write("-" * 20 + "\n")
            for i, iv_hex in enumerate(self.data.get('unique_ivs_hex', [])):
                f.write(f"IV {i+1}: {iv_hex}\n")
            f.write("\n")
            
            # Detailed function calls
            f.write("DETAILED FUNCTION CALLS\n")
            f.write("-" * 30 + "\n")
            for i, call in enumerate(self.data.get('function_calls', [])):
                f.write(f"Call {i+1}:\n")
                f.write(f"  Function: {call['function']}\n")
                f.write(f"  Timestamp: {call['timestamp']}\n")
                f.write(f"  Key: {call.get('key', 'N/A')}\n")
                f.write(f"  IV: {call.get('iv', 'N/A')}\n")
                f.write(f"  Data length: {call.get('data_length', 0)}\n")
                f.write(f"  Thread ID: {call.get('thread_id', 'N/A')}\n")
                f.write(f"  Address: {call.get('address', 'N/A')}\n\n")
                
        print(f"[+] Analysis report saved to: {output_file}")
        
    def export_keys_to_file(self, output_file=None):
        """Export keys to a separate file"""
        if not self.data:
            return
            
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"extracted_keys_{timestamp}.txt"
            
        with open(output_file, 'w') as f:
            f.write("# Extracted AES Keys\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            
            for i, (key_hex, key_b64) in enumerate(zip(
                self.data.get('unique_keys_hex', []),
                self.data.get('unique_keys_base64', [])
            )):
                f.write(f"# Key {i+1}\n")
                f.write(f"KEY_HEX_{i+1}={key_hex}\n")
                f.write(f"KEY_B64_{i+1}={key_b64}\n\n")
                
        print(f"[+] Keys exported to: {output_file}")
        
    def export_ivs_to_file(self, output_file=None):
        """Export IVs to a separate file"""
        if not self.data:
            return
            
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"extracted_ivs_{timestamp}.txt"
            
        with open(output_file, 'w') as f:
            f.write("# Extracted AES IVs\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            
            for i, (iv_hex, iv_b64) in enumerate(zip(
                self.data.get('unique_ivs_hex', []),
                self.data.get('unique_ivs_base64', [])
            )):
                f.write(f"# IV {i+1}\n")
                f.write(f"IV_HEX_{i+1}={iv_hex}\n")
                f.write(f"IV_B64_{i+1}={iv_b64}\n\n")
                
        print(f"[+] IVs exported to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="AES Data Analyzer")
    parser.add_argument("data_file", help="JSON file containing extracted AES data")
    parser.add_argument("-a", "--analyze", action="store_true", help="Run full analysis")
    parser.add_argument("-r", "--report", help="Generate analysis report file")
    parser.add_argument("-k", "--keys", help="Export keys to file")
    parser.add_argument("-i", "--ivs", help="Export IVs to file")
    parser.add_argument("--functions", action="store_true", help="Analyze function calls")
    parser.add_argument("--keys-only", action="store_true", help="Analyze keys only")
    parser.add_argument("--ivs-only", action="store_true", help="Analyze IVs only")
    parser.add_argument("--patterns", action="store_true", help="Analyze data patterns")
    
    args = parser.parse_args()
    
    analyzer = AESDataAnalyzer(args.data_file)
    
    if not analyzer.data:
        return
        
    # Run analysis based on arguments
    if args.analyze or not any([args.functions, args.keys_only, args.ivs_only, args.patterns]):
        analyzer.analyze_function_calls()
        analyzer.analyze_keys()
        analyzer.analyze_ivs()
        analyzer.analyze_data_patterns()
    else:
        if args.functions:
            analyzer.analyze_function_calls()
        if args.keys_only:
            analyzer.analyze_keys()
        if args.ivs_only:
            analyzer.analyze_ivs()
        if args.patterns:
            analyzer.analyze_data_patterns()
            
    # Generate reports
    if args.report:
        analyzer.generate_report(args.report)
    else:
        analyzer.generate_report()
        
    if args.keys:
        analyzer.export_keys_to_file(args.keys)
    else:
        analyzer.export_keys_to_file()
        
    if args.ivs:
        analyzer.export_ivs_to_file(args.ivs)
    else:
        analyzer.export_ivs_to_file()

if __name__ == "__main__":
    main()