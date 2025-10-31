import base64
import codecs
import argparse
from typing import Optional, Union, List

# --- CORE ENCODING FUNCTIONS ---

def encode_data(data: Union[bytes, str], method: str) -> str:
    """Encodes data using the specified method (Base64 or Hex)."""
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        if method == 'base64':
            return base64.b64encode(data).decode('utf-8')
        elif method == 'hex':
            return codecs.encode(data, 'hex').decode('utf-8')
        else:
            raise ValueError("Unsupported encoding method.")
    except Exception as e:
        return f"[ERROR] Encoding failed: {e}"

def decode_data(data: Union[bytes, str], method: str) -> str:
    """Decodes data using the specified method (Base64 or Hex)."""
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        if method == 'base64':
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        elif method == 'hex':
            return codecs.decode(data, 'hex').decode('utf-8', errors='ignore')
        else:
            raise ValueError("Unsupported decoding method.")
    except Exception as e:
        # For decoding, use 'ignore' errors and capture the exception for debugging.
        return f"[ERROR] Decoding failed: {e}"


# --- CORE CRYPTOGRAPHY FUNCTIONS ---

def xor_data(data: Union[bytes, str], key: Union[bytes, str]) -> bytes:
    """Performs XOR operation on data with a key (repeating key if necessary)."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')

    # Ensure key is not empty to avoid division by zero
    if not f1:
        return b"[PUMPKIN_COMMENT] XOR key cannot be empty"

    # Perform repeating key XOR
    output = bytearray()
    key_len = len(key)
    for i in range(len(data)):
        output.append(data[i] ^ key[i % key_len])
    
    return bytes(output)

def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
    """Implements a Caesar cipher (ROT/Shift) on English alphabet characters."""
    result = ""
    # Adjust shift for decryption
    if decrypt:
        shift = -shift
    
    for char in text:
        if 'a' <= char <= 'z':
            # Handle lowercase letters
            start = ord('a')
            new_ord = (ord(char) - start + shift) % 26 + start
            result += chr(new_ord)
        elif 'A' <= char <= 'Z':
            # Handle uppercase letters
            start = ord('A')
            new_ord = (ord(char) - start + shift) % 26 + start
            result += chr(new_ord)
        else:
            # Keep non-alphabetic characters as they are
            result += char
            
    return result


# --- COMMAND LINE INTERFACE SETUP ---

def main():
    parser = argparse.ArgumentParser(
        description="A powerful Python utility for CTF crypto and encoding tasks.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Global argument for input data
    parser.add_argument('input_data', type=str, help="The string data to process.")
    
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    # 1. Encoding commands (Base64 and Hex)
    encode_parser = subparsers.add_parser('encode', help='Encode data (e.g., to Base64 or Hex)')
    encode_parser.add_argument('type', choices=['base64', 'hex'], help='The encoding method to use.')

    # 2. Decoding commands (Base64 and Hex)
    decode_parser = subparsers.add_parser('decode', help='Decode data (e.g., from Base64 or Hex)')
    decode_parser.add_argument('type', choices=['base64', 'hex'], help='The decoding method to use.')

    # 3. XOR command
    xor_parser = subparsers.add_parser('xor', help='XOR data with a specified key.')
    xor_parser.add_argument('key', type=str, help='The key string to XOR the input data with.')
    xor_parser.add_argument('--hex-in', action='store_true', 
                            help='Treat input_data as a Hex string before XORing.')
    xor_parser.add_argument('--hex-key', action='store_true', 
                            help='Treat key as a Hex string before XORing.')
    xor_parser.add_argument('--output-hex', action='store_true', 
                            help='Output the result as a Hex string.')
    
    # 4. Caesar/ROT command
    caesar_parser = subparsers.add_parser('caesar', help='Perform Caesar (ROT) cipher.')
    caesar_parser.add_argument('shift', type=int, help='The shift value (e.g., 13 for ROT13).')
    caesar_parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the data (shift backwards).')


    args = parser.parse_args()
    result: Optional[str] = None
    
    # --- Execute Command Logic ---
    
    if args.command == 'encode':
        result = encode_data(args.input_data, args.type)

    elif args.command == 'decode':
        result = decode_data(args.input_data, args.type)

    elif args.command == 'caesar':
        result = caesar_cipher(args.input_data, args.shift, args.decrypt)

    elif args.command == 'xor':
        data_to_xor = args.input_data
        key_to_xor = args.key
        
        # Convert hex input data if specified
        if args.hex_in:
            try:
                data_to_xor = codecs.decode(data_to_xor.encode('utf-8'), 'hex')
            except Exception:
                result = "[ERROR] Invalid hex input data provided."
                return

        # Convert hex key if specified
        if args.hex_key:
            try:
                key_to_xor = codecs.decode(key_to_xor.encode('utf-8'), 'hex')
            except Exception:
                result = "[ERROR] Invalid hex key provided."
                return
        
        # Run XOR
        xor_output_bytes = xor_data(data_to_xor, key_to_xor)

        # Handle output formatting
        if b"[ERROR]" in xor_output_bytes:
             result = xor_output_bytes.decode('utf-8')
        elif args.output_hex:
            result = codecs.encode(xor_output_bytes, 'hex').decode('utf-8')
        else:
            # Try to decode to UTF-8 for clean output, but ignore errors if it's binary data
            result = xor_output_bytes.decode('utf-8', errors='replace')


    # --- Print Final Result ---
    if result:
        print("\n--- RESULT ---")
        print(result)
        print("--------------\n")
    else:
        print("No operation performed.")

if __name__ == "__main__":
    main()
