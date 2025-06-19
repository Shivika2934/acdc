# crypto_module.py
import random
import string
import base64
import logging
import re
import unicodedata
import logging
import json
import os
import time
from datetime import datetime
from typing import Dict, Optional, Tuple

# Set up detailed logging for auditing
logging.basicConfig(level=logging.INFO, filename="crypto_audit.log", filemode="w",
                    format="%(asctime)s - %(levelname)s - %(message)s")

# ------------------------------
# Utility Functions
# ------------------------------


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def remove_emojis(text: str) -> str:
    """Remove emojis and miscellaneous symbols from the text."""
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags
        "\U00002700-\U000027BF"  # other symbols
        "\U000024C2-\U0001F251"
        "]+", flags=re.UNICODE)
    cleaned = emoji_pattern.sub(r'', text)
    if cleaned != text:
        logging.info("Emojis removed from input.")
    return cleaned

def normalize_unicode(text: str) -> str:
    """Normalize Unicode text to NFC form."""
    normalized = unicodedata.normalize('NFC', text)
    if normalized != text:
        logging.info("Text normalized to NFC.")
    return normalized

def strip_and_collapse_whitespace(text: str) -> str:
    """Trim and reduce multiple spaces to a single space."""
    collapsed = re.sub(r'\s+', ' ', text.strip())
    if collapsed != text:
        logging.info("Whitespace cleaned.")
    return collapsed

def remove_punctuation(text: str) -> str:
    cleaned = re.sub(r'[^\w\s]', '', text)  # removes anything not a letter, digit, or whitespace
    if cleaned != text:
        logging.info("Punctuation removed from input.")
    return cleaned

def remove_non_printable(text: str) -> str:
    """Remove all non-printable characters."""
    filtered = ''.join(c for c in text if c.isprintable())
    if filtered != text:
        logging.info("Non-printable characters removed.")
    return filtered

def sanitize_input(text: str, lowercase: bool = False) -> str:
    """
    Sanitize input text by applying multiple cleanup steps:
    - Normalize Unicode
    - Remove emojis
    - Strip and collapse whitespace
    - Remove non-printable characters
    - Optionally lowercase
    """
    logging.info("Sanitizing input text...")
    original = text
    text = normalize_unicode(text)
    text = remove_emojis(text)
    text = strip_and_collapse_whitespace(text)
    text = remove_non_printable(text)
    text = remove_punctuation(text) 
    if lowercase:
        text = text.lower()
        logging.info("Text converted to lowercase.")

    if text != original:
        logging.info("Sanitization complete. Changes were made.")
    else:
        logging.info("No sanitization needed.")

    return text


# ------------------------------
# Monoalphabetic Substitution Cipher
# ------------------------------


# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("crypto_module.log"),
        logging.StreamHandler()
    ]
)

def save_key_to_file(key: Dict[str, str], reverse_key: Dict[str, str], filename: str = "monoalpha_key.json") -> None:
    """
    Saves the key and reverse key to a JSON file.
    """
    data = {
        "key": key,
        "reverse_key": reverse_key
    }
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"Monoalphabetic key saved to {filename}.")
    except IOError as e:
        logging.error(f"Error saving key to {filename}: {e}")

def load_key_from_file(filename: str = "monoalpha_key.json") -> Optional[Tuple[Dict[str, str], Dict[str, str]]]:
    """
    Loads the monoalphabetic key and reverse key from a file.
    Returns None if loading fails.
    """
    if not os.path.exists(filename):
        logging.warning(f"Key file {filename} not found.")
        return None

    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        logging.info(f"Monoalphabetic key loaded from {filename}.")
        return data["key"], data["reverse_key"]
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Failed to load key from file: {e}")
        return None

def validate_alphabet(alphabet: str) -> bool:
    """
    Validates that the provided alphabet contains 26 unique lowercase letters.
    """
    is_valid = (
        isinstance(alphabet, str) and
        len(alphabet) == 26 and
        all(char in string.ascii_lowercase for char in alphabet) and
        len(set(alphabet)) == 26
    )
    if not is_valid:
        logging.warning("Invalid alphabet provided for substitution key.")
    return is_valid

def generate_monoalpha_key(seed: Optional[int] = None, persist: bool = True) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Generates a monoalphabetic substitution cipher key.

    Args:
        seed (Optional[int]): Optional seed for reproducibility.
        persist (bool): Whether to save the key to a file.

    Returns:
        Tuple[Dict[str, str], Dict[str, str]]: Key and reverse key dictionaries.
    """
    start_time = time.time()
    logging.debug("Starting monoalphabetic key generation.")

    letters = list(string.ascii_lowercase)
    shuffled = letters[:]

    if seed is not None:
        logging.debug(f"Using seed {seed} for reproducibility.")
        random.seed(seed)

    attempt = 0
    while True:
        random.shuffle(shuffled)
        attempt += 1
        if len(set(shuffled)) == 26:
            break
        if attempt > 10:
            logging.error("Failed to generate valid substitution key after 10 attempts.")
            raise ValueError("Key generation failed.")

    key = dict(zip(letters, shuffled))
    reverse_key = {v: k for k, v in key.items()}

    logging.info(f"Monoalphabetic key successfully generated in {attempt} attempt(s).")
    logging.debug(f"Key: {key}")

    if persist:
        save_key_to_file(key, reverse_key)

    end_time = time.time()
    logging.debug(f"Key generation completed in {end_time - start_time:.4f} seconds.")

    return key, reverse_key




logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler("cipher.log"),
        logging.StreamHandler()
    ]
)

def monoalpha_encrypt(
    text: str,
    key: Dict[str, str],
    preserve_case: bool = True,
    log_metrics: bool = True,
    error_on_invalid: bool = False
) -> str:
    """
    Encrypts text using a monoalphabetic substitution cipher.

    Parameters:
    - text (str): The plaintext to be encrypted.
    - key (Dict[str, str]): Dictionary mapping original letters to encrypted letters.
    - preserve_case (bool): If True, maintains case sensitivity.
    - log_metrics (bool): If True, logs character statistics.
    - error_on_invalid (bool): If True, raises an error for missing keys.

    Returns:
    - str: Encrypted text.
    """
    logging.info("Starting monoalphabetic encryption.")
    if not text:
        logging.warning("Empty input text received.")
        return ""

    if not isinstance(key, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in key.items()):
        raise ValueError("Invalid key format. Expected a dictionary of str -> str.")

    encrypted_chars = []
    char_count = 0
    skipped_chars = 0

    for idx, char in enumerate(text):
        orig_char = char
        lower_char = char.lower()

        if lower_char in key:
            encrypted_char = key[lower_char]
            if preserve_case and char.isupper():
                encrypted_char = encrypted_char.upper()
            encrypted_chars.append(encrypted_char)
            logging.debug(f"Encrypted '{orig_char}' to '{encrypted_char}' at position {idx}")
            char_count += 1
        else:
            if error_on_invalid and char.isalpha():
                logging.error(f"Invalid character '{char}' at index {idx} with no mapping.")
                raise KeyError(f"No mapping for character: {char}")
            encrypted_chars.append(char)
            skipped_chars += 1
            logging.debug(f"Character '{char}' skipped at index {idx}.")

    result = ''.join(encrypted_chars)
    logging.info("Monoalphabetic encryption completed.")

    if log_metrics:
        logging.info(f"Total characters processed: {len(text)}")
        logging.info(f"Characters encrypted: {char_count}")
        logging.info(f"Characters skipped: {skipped_chars}")

    return result


def monoalpha_decrypt(
    ciphertext: str,
    key: Dict[str, str],
    preserve_case: bool = True,
    log_metrics: bool = True,
    error_on_invalid: bool = False
) -> str:
    """
    Decrypts text encrypted with a monoalphabetic substitution cipher.

    Parameters:
    - ciphertext (str): The encrypted text to decrypt.
    - key (Dict[str, str]): Dictionary mapping plaintext letters to cipher letters.
    - preserve_case (bool): If True, preserves the case of input characters.
    - log_metrics (bool): If True, logs detailed metrics about decryption.
    - error_on_invalid (bool): If True, raises KeyError on unmapped cipher chars.

    Returns:
    - str: The decrypted plaintext.
    """
    logging.info("Starting monoalphabetic decryption.")
    if not ciphertext:
        logging.warning("Empty ciphertext received for decryption.")
        return ""

    # Validate key: ensure it's a dict and correct format
    if not isinstance(key, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in key.items()):
        logging.error("Invalid key format provided for decryption.")
        raise ValueError("Key must be a dictionary of str -> str mappings.")

    # Build reverse key (cipher letter -> plain letter)
    reverse_key = {v.lower(): k.lower() for k, v in key.items()}

    decrypted_chars = []
    decrypted_count = 0
    skipped_count = 0

    for idx, char in enumerate(ciphertext):
        orig_char = char
        lower_char = char.lower()

        if lower_char in reverse_key:
            plain_char = reverse_key[lower_char]
            if preserve_case and char.isupper():
                plain_char = plain_char.upper()
            decrypted_chars.append(plain_char)
            logging.debug(f"Decrypted '{orig_char}' to '{plain_char}' at position {idx}.")
            decrypted_count += 1
        else:
            if error_on_invalid and char.isalpha():
                logging.error(f"Character '{char}' at index {idx} has no mapping in reverse key.")
                raise KeyError(f"No mapping for character: {char}")
            decrypted_chars.append(char)
            skipped_count += 1
            logging.debug(f"Skipped character '{char}' at position {idx} during decryption.")

    decrypted = ''.join(decrypted_chars)
    logging.info("Monoalphabetic decryption completed.")

    if log_metrics:
        logging.info(f"Total characters processed: {len(ciphertext)}")
        logging.info(f"Characters decrypted: {decrypted_count}")
        logging.info(f"Characters skipped: {skipped_count}")

    return decrypted



# ------------------------------
# XOR-Based Symmetric Block Cipher
# ------------------------------
def generate_xor_key(
    length: int = 8,
    charset: str = string.ascii_letters + string.digits + string.punctuation,
    seed: Optional[int] = None
) -> str:
    """
    Generates a random XOR key of given length.

    Parameters:
    - length (int): Length of the key (default 8).
    - charset (str): Characters to choose from for the key.
    - seed (Optional[int]): Optional seed for reproducibility.

    Returns:
    - str: Generated XOR key.
    """
    if seed is not None:
        random.seed(seed)
        logging.debug(f"Random seed set to {seed} for XOR key generation.")

    if length <= 0:
        logging.error("Invalid XOR key length requested: must be > 0.")
        raise ValueError("Key length must be a positive integer.")

    key = ''.join(random.choices(charset, k=length))
    logging.info(f"XOR key generated of length {length}: {key}")
    return key


def xor_encrypt(
    plaintext: str,
    key: str,
    output_encoding: Optional[str] = None,
    sanitize: bool = True
) -> bytes | str:
    """
    Encrypts plaintext using XOR cipher with the given key.

    Parameters:
    - plaintext (str): The text to encrypt.
    - key (str): The XOR key.
    - output_encoding (Optional[str]): If 'base64', returns base64-encoded string; if None, returns raw bytes.
    - sanitize (bool): Whether to sanitize input text before encryption.

    Returns:
    - bytes or str: Encrypted data as bytes or base64 string.
    """
    logging.info("Starting XOR encryption.")

    if not plaintext:
        logging.warning("Empty plaintext provided for XOR encryption.")
        return b'' if output_encoding is None else ''

    if not key:
        logging.error("Empty key provided for XOR encryption.")
        raise ValueError("Key must be a non-empty string.")

    if sanitize:
        plaintext = sanitize_input(plaintext)
        logging.debug(f"Plaintext after sanitization: {plaintext}")

    key_bytes = key.encode('utf-8')
    plaintext_bytes = plaintext.encode('utf-8')

    cipher_bytes = bytes(
        [plaintext_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(plaintext_bytes))]
    )

    logging.info(f"XOR encryption completed. Plaintext length: {len(plaintext_bytes)} bytes.")

    if output_encoding == 'base64':
        encoded = base64.b64encode(cipher_bytes).decode('utf-8')
        logging.debug("Ciphertext base64-encoded for output.")
        return encoded

    return cipher_bytes

def xor_decrypt(
    ciphertext: bytes | str,
    key: str,
    input_encoding: Optional[str] = None,
    sanitize: bool = True
) -> str:
    """
    Decrypts XOR-encrypted ciphertext using the given key.

    Parameters:
    - ciphertext (bytes or str): The ciphertext to decrypt.
      If input_encoding='base64', ciphertext should be a base64-encoded string.
      Otherwise, ciphertext should be raw bytes.
    - key (str): The XOR key used for decryption.
    - input_encoding (Optional[str]): If 'base64', decode ciphertext from base64 before decrypting.
    - sanitize (bool): Whether to sanitize output text after decryption.

    Returns:
    - str: The decrypted plaintext as a UTF-8 string.
    """
    logging.info("Starting XOR decryption.")

    if not ciphertext:
        logging.warning("Empty ciphertext received for XOR decryption.")
        return ""

    if not key:
        logging.error("Empty key provided for XOR decryption.")
        raise ValueError("Key must be a non-empty string.")

    try:
        if input_encoding == 'base64' and isinstance(ciphertext, str):
            ciphertext_bytes = base64.b64decode(ciphertext)
            logging.debug("Ciphertext base64-decoded before decryption.")
        elif isinstance(ciphertext, bytes):
            ciphertext_bytes = ciphertext
        else:
            logging.error("Invalid ciphertext type or encoding mismatch.")
            raise ValueError("Ciphertext must be bytes or base64 string if input_encoding='base64'.")
    except (base64.binascii.Error, ValueError) as e:
        logging.error(f"Failed to decode ciphertext: {e}")
        raise

    key_bytes = key.encode('utf-8')

    decrypted_bytes = bytes(
        [ciphertext_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(ciphertext_bytes))]
    )

    try:
        decrypted_text = decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        logging.error(f"Failed to decode decrypted bytes to UTF-8 string: {e}")
        raise

    if sanitize:
        decrypted_text = sanitize_input(decrypted_text)
        logging.debug("Decrypted text sanitized after XOR decryption.")

    logging.info("XOR decryption completed successfully.")
    return decrypted_text



# ------------------------------
# Extended Cipher Interface with Persistence
# ------------------------------
def save_key_to_file(
    key: Dict[str, str],
    filename: str,
    mode: str = "w",
    save_reverse_key: bool = False
) -> None:
    """
    Saves a monoalphabetic cipher key dictionary to a file.

    Parameters:
    - key (Dict[str, str]): The key dictionary to save.
    - filename (str): Path to the file to save the key.
    - mode (str): File open mode, 'w' to overwrite, 'a' to append (default 'w').
    - save_reverse_key (bool): Whether to save the reverse key as well (default False).

    Returns:
    - None
    """
    try:
        with open(filename, mode, encoding='utf-8') as file:
            # Save main key
            for k, v in key.items():
                file.write(f"{k}:{v}\n")
            logging.info(f"Key saved to {filename} (mode={mode}).")

            # Optionally save reverse key
            if save_reverse_key:
                reverse_key = {v: k for k, v in key.items()}
                file.write("\n# Reverse Key\n")
                for k, v in reverse_key.items():
                    file.write(f"{k}:{v}\n")
                logging.info(f"Reverse key also saved to {filename}.")
    except IOError as e:
        logging.error(f"Failed to save key to {filename}: {e}")
        raise


def load_key_from_file(filename: str, validate: bool = True) -> Dict[str, str]:
    """
    Loads a monoalphabetic cipher key dictionary from a file.

    Parameters:
    - filename (str): Path to the file to load the key from.
    - validate (bool): Whether to validate that the loaded key is valid (default True).

    Returns:
    - Dict[str, str]: The loaded key dictionary.

    Raises:
    - FileNotFoundError: If the file does not exist.
    - ValueError: If the file content is invalid or key validation fails.
    """
    key = {}
    try:
        with open(filename, "r", encoding='utf-8') as file:
            for line_number, line in enumerate(file, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue  # Skip empty lines or comments
                if ':' not in line:
                    logging.warning(f"Skipping malformed line {line_number} in {filename}: '{line}'")
                    continue
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if len(k) != 1 or len(v) != 1:
                    logging.warning(f"Invalid key-value pair on line {line_number}: '{line}'")
                    continue
                key[k] = v

        if validate:
            # Validate loaded key
            if not validate_alphabet(''.join(sorted(key.keys()))):
                raise ValueError(f"Loaded key from {filename} failed validation: keys invalid or incomplete.")
            if not validate_alphabet(''.join(sorted(key.values()))):
                raise ValueError(f"Loaded key from {filename} failed validation: values invalid or incomplete.")

        logging.info(f"Key successfully loaded and validated from {filename}.")
        return key
    except FileNotFoundError as e:
        logging.error(f"Key file {filename} not found: {e}")
        raise
    except IOError as e:
        logging.error(f"Error reading key file {filename}: {e}")
        raise



def save_encrypted_data(
    data: bytes,
    filename: str,
    backup: bool = False,
    metadata: dict = None
) -> None:
    """
    Save encrypted binary data to a file, optionally backing up existing file and saving metadata.

    Parameters:
    - data (bytes): The encrypted data to write.
    - filename (str): The target filename.
    - backup (bool): If True, creates a backup of existing file by renaming before overwriting.
    - metadata (dict): Optional metadata to save alongside data (e.g., JSON in a separate .meta file).

    Returns:
    - None
    """
    try:
        # Backup existing file if needed
        if backup and os.path.exists(filename):
            backup_filename = filename + ".bak"
            os.replace(filename, backup_filename)
            logging.info(f"Existing file backed up as {backup_filename}.")

        # Write encrypted data
        with open(filename, "wb") as file:
            file.write(data)
        logging.info(f"Encrypted data saved to {filename}.")

        # Save metadata if provided (JSON sidecar file)
        if metadata is not None:
            meta_filename = filename + ".meta.json"
            try:
                with open(meta_filename, "w", encoding="utf-8") as meta_file:
                    json.dump(metadata, meta_file, indent=4)
                logging.info(f"Metadata saved to {meta_filename}.")
            except Exception as e:
                logging.warning(f"Failed to save metadata to {meta_filename}: {e}")

    except IOError as e:
        logging.error(f"Failed to save encrypted data to {filename}: {e}")
        raise


def load_encrypted_data(filename: str, load_metadata: bool = False) -> Tuple[bytes, Optional[dict]]:
    """
    Load encrypted binary data from a file, optionally loading associated metadata.

    Parameters:
    - filename (str): The filename to load data from.
    - load_metadata (bool): If True, attempts to load accompanying metadata from a JSON sidecar file.

    Returns:
    - Tuple[bytes, Optional[dict]]: Tuple containing the loaded encrypted data and optionally metadata dictionary.
    
    Raises:
    - FileNotFoundError: If the data file does not exist.
    - IOError: For general file reading errors.
    """
    metadata = None
    try:
        with open(filename, "rb") as file:
            data = file.read()
        logging.info(f"Encrypted data loaded from {filename}.")

        if load_metadata:
            meta_filename = filename + ".meta.json"
            if os.path.exists(meta_filename):
                try:
                    with open(meta_filename, "r", encoding="utf-8") as meta_file:
                        metadata = json.load(meta_file)
                    logging.info(f"Metadata loaded from {meta_filename}.")
                except Exception as e:
                    logging.warning(f"Failed to load metadata from {meta_filename}: {e}")

        return data, metadata

    except FileNotFoundError as e:
        logging.error(f"Encrypted data file not found: {filename}")
        raise
    except IOError as e:
        logging.error(f"Failed to load encrypted data from {filename}: {e}")
        raise



# ------------------------------
# User Interface for Testing
# ------------------------------
def demo_monoalpha(
    text: str,
    sanitize_input_flag: bool = True,
    save_keys: bool = False,
    key_filename: str = "monoalpha_key_demo.json"
):
    """
    Demonstrates the full monoalphabetic substitution cipher process:
    - Generates a cipher key
    - Optionally sanitizes input text
    - Encrypts the text
    - Decrypts the encrypted text
    - Prints detailed output
    - Optionally saves the key to a file

    Parameters:
    - text (str): The input plaintext to encrypt and decrypt.
    - sanitize_input_flag (bool): If True, applies input sanitization.
    - save_keys (bool): If True, saves the generated key and reverse key to disk.
    - key_filename (str): Filename for saving/loading keys.

    Returns:
    None
    """
    logging.info("Starting monoalphabetic cipher demo...")

    try:
        original_text = text
        if sanitize_input_flag:
            logging.info("Sanitizing input text for demo.")
            text = sanitize_input(text, lowercase=False)

        # Generate key and reverse key
        key, reverse_key = generate_monoalpha_key(persist=False)
        logging.debug(f"Generated key: {key}")

        # Encrypt
        start_encrypt = time.time()
        encrypted = monoalpha_encrypt(text, key, preserve_case=True)
        end_encrypt = time.time()

        # Decrypt
        start_decrypt = time.time()
        decrypted = monoalpha_decrypt(encrypted, key)
        end_decrypt = time.time()

        # Save keys optionally
        if save_keys:
            save_key_to_file(key, key_filename)
            logging.info(f"Keys saved to {key_filename}")

        # Display results
        print("\n--- Monoalphabetic Cipher Demo ---")
        print(f"Original Text           : {original_text}")
        print(f"Sanitized Input         : {text}")
        print(f"Encrypted Text          : {encrypted}")
        print(f"Decrypted Text          : {decrypted}")
        print(f"Encryption Time (secs)  : {end_encrypt - start_encrypt:.6f}")
        print(f"Decryption Time (secs)  : {end_decrypt - start_decrypt:.6f}")

        # Verify correctness
        if sanitize_input_flag:
            # Because sanitization might have altered original input,
            # compare decrypted with sanitized input
            success = decrypted == text
        else:
            success = decrypted == original_text

        print(f"Decryption successful   : {success}")
        logging.info(f"Monoalphabetic cipher demo completed. Success: {success}")

    except Exception as e:
        logging.error(f"Error during monoalphabetic cipher demo: {e}")
        print(f"An error occurred during demo: {e}")



def demo_xor(
    text: str,
    sanitize_input_flag: bool = True,
    save_key: bool = False,
    key_filename: str = "xor_key_demo.txt"
):
    """
    Demonstrates XOR symmetric cipher process:
    - Generates a random key
    - Optionally sanitizes input text
    - Encrypts the text using XOR cipher
    - Decrypts the ciphertext
    - Prints detailed outputs
    - Optionally saves the key to a file

    Parameters:
    - text (str): Input plaintext to encrypt and decrypt.
    - sanitize_input_flag (bool): If True, sanitizes the input before encryption.
    - save_key (bool): If True, saves the generated XOR key to disk.
    - key_filename (str): Filename to save/load the XOR key.

    Returns:
    None
    """
    logging.info("Starting XOR cipher demo...")

    try:
        original_text = text
        if sanitize_input_flag:
            logging.info("Sanitizing input text for XOR demo.")
            text = sanitize_input(text, lowercase=False)

        # Generate XOR key
        key = generate_xor_key(length=max(8, len(text)//2))  # key length adaptive
        logging.debug(f"Generated XOR key: {key}")

        # Encrypt
        start_encrypt = time.time()
        encrypted_bytes = xor_encrypt(text, key)
        end_encrypt = time.time()

        # Decrypt
        start_decrypt = time.time()
        decrypted_text = xor_decrypt(encrypted_bytes, key)
        end_decrypt = time.time()

        # Save key optionally
        if save_key:
            with open(key_filename, 'w') as kf:
                kf.write(key)
            logging.info(f"XOR key saved to {key_filename}")

        # Display results
        print("\n--- XOR Symmetric Cipher Demo ---")
        print(f"Original Text           : {original_text}")
        print(f"Sanitized Input         : {text}")
        print(f"Key                    : {key}")
        print(f"Encrypted (Base64)      : {base64.b64encode(encrypted_bytes).decode()}")
        print(f"Decrypted Text          : {decrypted_text}")
        print(f"Encryption Time (secs)  : {end_encrypt - start_encrypt:.6f}")
        print(f"Decryption Time (secs)  : {end_decrypt - start_decrypt:.6f}")

        # Verify correctness
        success = decrypted_text == text
        print(f"Decryption successful   : {success}")
        logging.info(f"XOR cipher demo completed. Success: {success}")

    except Exception as e:
        logging.error(f"Error during XOR cipher demo: {e}")
        print(f"An error occurred during XOR cipher demo: {e}")


def main():
    """Main function"""
    from ui_utils import init_ui, print_header, print_status, create_menu, Colors
    
    init_ui()
    print_header("Cryptographic Analysis Module")

    history_file = "crypto_history.json"
    history = []

    if os.path.exists(history_file):
        try:
            with open(history_file, 'r') as f:
                history = json.load(f)
            print_status(f"Loaded {len(history)} historical records", "INFO")
        except Exception as e:
            print_status(f"Failed to load history: {e}", "ERROR")

    try:
        while True:
            choice = create_menu([
                "Encrypt Message",
                "Decrypt Message",
                "View History",
                "Run Analysis Demo",
                "Exit"
            ], "Cryptographic Operations")

            if choice == 1 or choice == 2:
                action = 'e' if choice == 1 else 'd'
                
                method = create_menu([
                    "XOR Cipher",
                    "Monoalphabetic Cipher",
                    "Back to Main Menu"
                ], "Choose Cipher Method")

                if method == 3:
                    continue

                text = input(f"\n{Colors.BOLD}Enter the text: {Colors.ENDC}").strip()
                if not text:
                    print_status("Text cannot be empty!", "ERROR")
                    continue

                key = input(f"{Colors.BOLD}Enter encryption key: {Colors.ENDC}").strip()
                if not key:
                    print_status("Key cannot be empty!", "ERROR")
                    continue

                try:
                    if method == 1:  # XOR
                        if action == 'e':
                            result = xor_encrypt(text, key, output_encoding='base64')
                            print_status("Text encrypted successfully", "SUCCESS")
                        else:
                            result = xor_decrypt(text, key, input_encoding='base64')
                            print_status("Text decrypted successfully", "SUCCESS")
                    else:  # Monoalphabetic
                        if not validate_alphabet(key):
                            print_status("Invalid key! Must be 26 unique lowercase letters.", "ERROR")
                            continue
                            
                        key_dict = dict(zip(string.ascii_lowercase, key))
                        if action == 'e':
                            result = monoalpha_encrypt(text, key_dict)
                            print_status("Text encrypted successfully", "SUCCESS")
                        else:
                            decrypt_key = dict(zip(key, string.ascii_lowercase))
                            result = monoalpha_decrypt(text, decrypt_key)
                            print_status("Text decrypted successfully", "SUCCESS")

                    print(f"\n{Colors.CYAN}Result:{Colors.ENDC} {result}\n")

                    # Save to history
                    history.append({
                        "timestamp": datetime.now().isoformat(),
                        "type": "XOR" if method == 1 else "Monoalphabetic",
                        "action": "encrypt" if action == 'e' else "decrypt",
                        "input": text,
                        "result": result
                    })

                except Exception as e:
                    print_status(f"Operation failed: {e}", "ERROR")

            elif choice == 3:  # View History
                if not history:
                    print_status("No history available", "WARNING")
                    continue
                    
                print_header("Operation History")
                for entry in history[-10:]:  # Show last 10 entries
                    ts = datetime.fromisoformat(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                    print(f"\n{Colors.CYAN}[{ts}] {entry['type']} {entry['action'].upper()}{Colors.ENDC}")
                    print(f"Input : {entry['input']}")
                    print(f"Result: {entry['result']}")

            elif choice == 4:  # Demo
                text = "Hello, World! 123 #@$"
                print_status("Running cryptanalysis demo...", "INFO")
                demo_monoalpha(text)
                demo_xor(text)

            else:  # Exit
                break

            # Save history
            try:
                with open(history_file, 'w') as f:
                    json.dump(history, f, indent=4)
            except Exception as e:
                print_status(f"Failed to save history: {e}", "ERROR")

    except KeyboardInterrupt:
        print_status("\nExiting...", "INFO")


if __name__ == "__main__":
    main()