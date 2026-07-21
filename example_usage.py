#!/usr/bin/env python3
"""
Example script for using extracted AES keys and IVs from Frida hook
نمونه اسکریپت برای استفاده از کلیدها و IV های استخراج شده از فریدا
"""

import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def hex_to_bytes(hex_string):
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_string)

def base64_to_bytes(base64_string):
    """Convert base64 string to bytes"""
    return base64.b64decode(base64_string)

def decrypt_with_extracted_key(encrypted_data, key_hex, iv_hex, mode=AES.MODE_CBC):
    """
    Decrypt data using extracted key and IV
    
    Args:
        encrypted_data: Base64 encoded encrypted data
        key_hex: Hex string of the key
        iv_hex: Hex string of the IV
        mode: AES mode (CBC, ECB, etc.)
    
    Returns:
        Decrypted data as string
    """
    try:
        # Convert hex strings to bytes
        key = hex_to_bytes(key_hex)
        iv = hex_to_bytes(iv_hex)
        
        # Decode encrypted data
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Create cipher
        if mode == AES.MODE_ECB:
            cipher = AES.new(key, mode)
        else:
            cipher = AES.new(key, mode, iv)
        
        # Decrypt
        decrypted = cipher.decrypt(encrypted_bytes)
        
        # Remove padding
        try:
            unpadded = unpad(decrypted, AES.block_size)
            return unpadded.decode('utf-8')
        except ValueError:
            # If unpadding fails, return raw decrypted data
            return decrypted.decode('utf-8', errors='ignore')
            
    except Exception as e:
        print(f"Error decrypting: {e}")
        return None

def encrypt_with_extracted_key(plaintext, key_hex, iv_hex, mode=AES.MODE_CBC):
    """
    Encrypt data using extracted key and IV
    
    Args:
        plaintext: Text to encrypt
        key_hex: Hex string of the key
        iv_hex: Hex string of the IV
        mode: AES mode (CBC, ECB, etc.)
    
    Returns:
        Base64 encoded encrypted data
    """
    try:
        # Convert hex strings to bytes
        key = hex_to_bytes(key_hex)
        iv = hex_to_bytes(iv_hex)
        
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Create cipher
        if mode == AES.MODE_ECB:
            cipher = AES.new(key, mode)
        else:
            cipher = AES.new(key, mode, iv)
        
        # Encrypt
        padded = pad(plaintext_bytes, AES.block_size)
        encrypted = cipher.encrypt(padded)
        
        # Return base64 encoded
        return base64.b64encode(encrypted).decode('utf-8')
        
    except Exception as e:
        print(f"Error encrypting: {e}")
        return None

def analyze_extracted_data(keys, ivs, encrypted_data):
    """
    Analyze and test extracted data
    
    Args:
        keys: List of extracted keys
        ivs: List of extracted IVs
        encrypted_data: List of encrypted data
    """
    print("=" * 60)
    print("ANALYZING EXTRACTED DATA")
    print("=" * 60)
    
    # Test each key and IV combination
    for i, key in enumerate(keys):
        print(f"\nTesting Key {i+1}:")
        print(f"  Hex: {key['hex']}")
        print(f"  Base64: {key['base64']}")
        print(f"  Size: {key['size']} bytes")
        print(f"  Source: {key.get('source', 'unknown')}")
        
        # Try to decrypt each encrypted data with this key
        for j, iv in enumerate(ivs):
            print(f"\n  With IV {j+1}:")
            print(f"    Hex: {iv['hex']}")
            print(f"    Base64: {iv['base64']}")
            
            # Test decryption with each encrypted data
            for k, data in enumerate(encrypted_data):
                if data['type'] == 'output':  # Only try to decrypt output data
                    print(f"\n    Trying to decrypt data {k+1}:")
                    print(f"      Encrypted (Base64): {data['base64']}")
                    
                    # Try different AES modes
                    modes = [AES.MODE_CBC, AES.MODE_ECB]
                    mode_names = ['CBC', 'ECB']
                    
                    for mode, mode_name in zip(modes, mode_names):
                        try:
                            if mode == AES.MODE_ECB:
                                # ECB doesn't use IV
                                decrypted = decrypt_with_extracted_key(
                                    data['base64'], 
                                    key['hex'], 
                                    iv['hex'], 
                                    mode
                                )
                            else:
                                decrypted = decrypt_with_extracted_key(
                                    data['base64'], 
                                    key['hex'], 
                                    iv['hex'], 
                                    mode
                                )
                            
                            if decrypted:
                                print(f"      {mode_name} Decrypted: {decrypted}")
                                
                                # Check if it looks like valid data
                                if len(decrypted) > 0 and len(decrypted) < 1000:
                                    print(f"      {mode_name} Length: {len(decrypted)} chars")
                                    
                                    # Check if it's printable
                                    if decrypted.isprintable():
                                        print(f"      {mode_name} Printable: Yes")
                                    else:
                                        print(f"      {mode_name} Printable: No")
                                        
                        except Exception as e:
                            print(f"      {mode_name} Error: {e}")

def save_extracted_data(keys, ivs, encrypted_data, filename="extracted_data.json"):
    """
    Save extracted data to JSON file
    
    Args:
        keys: List of extracted keys
        ivs: List of extracted IVs
        encrypted_data: List of encrypted data
        filename: Output filename
    """
    data = {
        'keys': keys,
        'ivs': ivs,
        'encrypted_data': encrypted_data,
        'timestamp': json.dumps(datetime.datetime.now().isoformat())
    }
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Data saved to {filename}")

def load_extracted_data(filename="extracted_data.json"):
    """
    Load extracted data from JSON file
    
    Args:
        filename: Input filename
    
    Returns:
        Tuple of (keys, ivs, encrypted_data)
    """
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        
        return data.get('keys', []), data.get('ivs', []), data.get('encrypted_data', [])
    except FileNotFoundError:
        print(f"File {filename} not found")
        return [], [], []
    except json.JSONDecodeError:
        print(f"Error parsing {filename}")
        return [], [], []

# Example usage
if __name__ == "__main__":
    import datetime
    
    # Example extracted data (replace with actual data from Frida)
    example_keys = [
        {
            'hex': '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
            'base64': 'ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8=',
            'size': 32,
            'source': 'AES_set_encrypt_key',
            'timestamp': '2024-01-15T10:30:45.123Z'
        }
    ]
    
    example_ivs = [
        {
            'hex': '1234567890abcdef1234567890abcdef',
            'base64': 'EjRWeJq83vEjRWeJq83v',
            'size': 16,
            'source': 'EVP_EncryptInit_ex',
            'timestamp': '2024-01-15T10:30:45.124Z'
        }
    ]
    
    example_encrypted_data = [
        {
            'type': 'output',
            'hex': 'a1b2c3d4e5f67890a1b2c3d4e5f67890',
            'base64': 'obLD1OX2eJChssPU5fZ4kA==',
            'size': 16,
            'timestamp': '2024-01-15T10:30:45.125Z'
        }
    ]
    
    print("Example AES Key/IV Analysis")
    print("=" * 40)
    
    # Analyze the data
    analyze_extracted_data(example_keys, example_ivs, example_encrypted_data)
    
    # Save data
    save_extracted_data(example_keys, example_ivs, example_encrypted_data)
    
    # Example encryption/decryption
    print("\n" + "=" * 40)
    print("Example Encryption/Decryption")
    print("=" * 40)
    
    test_message = "Hello, this is a test message!"
    print(f"Original message: {test_message}")
    
    # Encrypt
    encrypted = encrypt_with_extracted_key(
        test_message, 
        example_keys[0]['hex'], 
        example_ivs[0]['hex']
    )
    print(f"Encrypted (Base64): {encrypted}")
    
    # Decrypt
    decrypted = decrypt_with_extracted_key(
        encrypted, 
        example_keys[0]['hex'], 
        example_ivs[0]['hex']
    )
    print(f"Decrypted: {decrypted}")
    
    print("\nScript completed successfully!")