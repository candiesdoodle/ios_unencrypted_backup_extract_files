# -*- coding: utf-8 -*-
"""
iphone_backup_extractor.py

Combines functionality to extract files from both encrypted and unencrypted
iOS backups found on disk.

Based on the original separate files:
- iphone_backup.py
- utils.py
- google_iphone_dataprotection.py

Original iphone-dataprotection code derived from:
https://code.google.com/p/iphone-dataprotection/
Original License: https://opensource.org/licenses/BSD-3-Clause

Requires: pycryptodome
Optional (for faster PBKDF2): fastpbkdf2
"""

import os
import os.path
import plistlib
import shutil
import sqlite3
import struct
import tempfile
from contextlib import contextmanager

# Cryptography Imports (conditional for unencrypted backups)
try:
    import Crypto.Cipher.AES
    import Crypto.Hash
    import Crypto.Protocol.KDF
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False
    # Define dummy classes/functions if crypto is not needed/available
    # This allows the script to load even if pycryptodome isn't installed,
    # failing later only if decryption is actually attempted.
    class Crypto:
        class Cipher:
            class AES:
                MODE_CBC = None
                MODE_ECB = None
                @staticmethod
                def new(*args, **kwargs):
                    raise ImportError("pycryptodome is required for encrypted backups.")
        class Hash:
            SHA1 = None
            SHA256 = None
        class Protocol:
            class KDF:
                @staticmethod
                def PBKDF2(*args, **kwargs):
                     raise ImportError("pycryptodome is required for encrypted backups.")

# PBKDF2 Implementation Selection
_FASTPBKDF2_AVAILABLE = False
if _CRYPTO_AVAILABLE:
    try:
        # Prefer a fast, pure C++ implementation:
        from fastpbkdf2 import pbkdf2_hmac
        _FASTPBKDF2_AVAILABLE = True
    except ImportError:
        # Otherwise, use pycryptodome - wrapping it to look like the standard library method signature.
        # It is 2-3x faster than the standard library 'hashlib.pbkdf2_hmac' method, but still 2x slower than fastpbkdf2.
        _HASH_FNS = {"sha1": Crypto.Hash.SHA1, "sha256": Crypto.Hash.SHA256}

        def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
            if not _CRYPTO_AVAILABLE:
                 raise ImportError("pycryptodome is required for encrypted backups.")
            hash_module = _HASH_FNS.get(hash_name)
            if not hash_module:
                raise ValueError(f"Unsupported hash algorithm for PBKDF2: {hash_name}")
            return Crypto.Protocol.KDF.PBKDF2(password, salt, dklen, count=iterations, hmac_hash_module=hash_module)

# --- Constants and Helper Classes (from utils.py) ---

_CBC_BLOCK_SIZE = 16  # bytes.
_CHUNK_SIZE = 1024**2  # 1MB blocks, must be a multiple of 16 bytes.

class RelativePath:
    """Relative paths for commonly accessed files."""
    ADDRESS_BOOK = "Library/AddressBook/AddressBook.sqlitedb"
    TEXT_MESSAGES = "Library/SMS/sms.db"
    CALL_HISTORY = "Library/CallHistoryDB/CallHistory.storedata"
    NOTES = "Library/Notes/notes.sqlite"
    CALENDARS = "Library/Calendar/Calendar.sqlitedb"
    HEALTH = "Health/healthdb.sqlite"
    HEALTH_SECURE = "Health/healthdb_secure.sqlite"
    SAFARI_HISTORY = "Library/Safari/History.db"
    SAFARI_BOOKMARKS = "Library/Safari/Bookmarks.db"
    WHATSAPP_MESSAGES = "ChatStorage.sqlite" # Needs correct domain
    WHATSAPP_CONTACTS = "ContactsV2.sqlite"  # Needs correct domain

class RelativePathsLike:
    """Relative path wildcards for commonly accessed groups of files."""
    ALL_FILES = "%"
    CAMERA_ROLL = "Media/DCIM/%APPLE/IMG%.%"
    ICLOUD_PHOTOS = "Media/PhotoData/CPLAssets/group%/%.%"
    SMS_ATTACHMENTS = "Library/SMS/Attachments/%.%"
    VOICEMAILS = "Library/Voicemail/%.amr"
    VOICE_RECORDINGS = "Library/Recordings/%"
    ICLOUD_LOCAL_FILES = "Library/Mobile Documents/com~apple~CloudDocs/%"
    WHATSAPP_ATTACHED_IMAGES = "Message/Media/%.jpg" # Needs correct domain
    WHATSAPP_ATTACHED_VIDEOS = "Message/Media/%.mp4" # Needs correct domain
    WHATSAPP_ATTACHMENTS = "Message/Media/%.%"      # Needs correct domain

class DomainLike:
    """Domain wildcards for commonly accessed apps and services."""
    HOME_DOMAIN = "HomeDomain"
    CAMERA_ROLL = "CameraRollDomain"
    MEDIA_DOMAIN = "MediaDomain" # Often used for recordings/voicemails
    FILES_ON_IPHONE = "AppDomainGroup-group.com.apple.FileProvider.LocalStorage"
    WHATSAPP = "AppDomainGroup-group.net.whatsapp.WhatsApp.shared"

class MatchFiles:
    """Paired relative paths and domains for more complex matching.

       Use items from this class with IosBackupExtractor.extract_files, e.g:
           backup.extract_files(**MatchFiles.CAMERA_ROLL, output_folder="./output")
    """
    CAMERA_ROLL = {"relative_paths_like": RelativePathsLike.CAMERA_ROLL, "domain_like": DomainLike.CAMERA_ROLL}
    ICLOUD_PHOTOS = {"relative_paths_like": RelativePathsLike.ICLOUD_PHOTOS, "domain_like": DomainLike.CAMERA_ROLL}
    SMS_ATTACHMENTS = {"relative_paths_like": RelativePathsLike.SMS_ATTACHMENTS, "domain_like": DomainLike.HOME_DOMAIN}
    VOICEMAILS = {"relative_paths_like": RelativePathsLike.VOICEMAILS, "domain_like": DomainLike.HOME_DOMAIN}
    VOICE_RECORDINGS = {"relative_paths_like": RelativePathsLike.VOICE_RECORDINGS, "domain_like": DomainLike.MEDIA_DOMAIN}
    ICLOUD_LOCAL_FILES = {"relative_paths_like": RelativePathsLike.ICLOUD_LOCAL_FILES, "domain_like": DomainLike.FILES_ON_IPHONE}
    WHATSAPP_MESSAGES = {"relative_path": RelativePath.WHATSAPP_MESSAGES, "domain_like": DomainLike.WHATSAPP}
    WHATSAPP_CONTACTS = {"relative_path": RelativePath.WHATSAPP_CONTACTS, "domain_like": DomainLike.WHATSAPP}
    WHATSAPP_ATTACHMENTS = {"relative_paths_like": RelativePathsLike.WHATSAPP_ATTACHMENTS, "domain_like": DomainLike.WHATSAPP}
    WHATSAPP_CONTACT_PHOTOS = {"relative_paths_like": "Media/Profile/%.jpg", "domain_like": DomainLike.WHATSAPP}
    # Examples for specific apps:
    CHROME_DOWNLOADS = {"relative_paths_like": "Documents/%", "domain_like": "AppDomain-com.google.chrome.ios"}
    STRAVA_WORKOUTS = {"relative_paths_like": "Documents/%.fit", "domain_like": "AppDomain-com.strava.stravaride"}


class FilePlist:
    """Represent a Manifest.db file-record PList object."""
    def __init__(self, bplist_bytes):
        self.is_valid = False
        self.plist = None
        self.data = None
        self.mtime = None
        self.filesize = 0
        self.protection_class = None
        self.encryption_key = None

        try:
            self.plist = plistlib.loads(bplist_bytes)
            # Find the root object, accounting for different plist structures
            if '$top' in self.plist and 'root' in self.plist['$top']:
                root_ref = self.plist['$top']['root']
                # Handle UID objects (newer plists)
                if isinstance(root_ref, plistlib.UID):
                   root_ref_data = root_ref.data
                # Handle integer references (older plists?)
                elif isinstance(root_ref, int):
                    root_ref_data = root_ref
                else:
                     # Fallback or raise if unexpected type
                     print(f"WARN: Unexpected root reference type in FilePlist: {type(root_ref)}")
                     return # Cannot proceed

                if '$objects' in self.plist and len(self.plist['$objects']) > root_ref_data:
                     self.data = self.plist['$objects'][root_ref_data]
                else:
                     print("WARN: Could not find '$objects' or root reference out of bounds in FilePlist.")
                     return # Cannot proceed
            else:
                # Assume the plist itself is the root dictionary if $top/root is missing
                self.data = self.plist
                print("WARN: FilePlist missing '$top'/'root', assuming root object.")


            # Common and useful attributes:
            self.mtime = self.data.get("LastModified") # This is often a datetime object
            self.filesize = int(self.data.get("Size", 0))
            self.protection_class = self.data.get('ProtectionClass') # Might be missing in unencrypted

            # Encryption key data structure differs slightly
            encryption_key_obj = self.data.get('EncryptionKey')
            if encryption_key_obj and isinstance(encryption_key_obj, plistlib.UID):
                key_ref = encryption_key_obj.data
                if '$objects' in self.plist and len(self.plist['$objects']) > key_ref:
                   key_data_obj = self.plist['$objects'][key_ref]
                   # Look for NS.data or similar standard data wrapper keys
                   if isinstance(key_data_obj, dict):
                       if 'NS.data' in key_data_obj: # Common case
                           self.encryption_key = key_data_obj['NS.data'][4:] # Skip 4 byte class num
                       else:
                           # Check for other possible data keys if necessary (less common)
                           # Example: Maybe just raw bytes in some plist version?
                           # Adapt based on observed plist structures if needed.
                           print(f"WARN: Unknown EncryptionKey data structure: {key_data_obj.keys()}")
                else:
                     print("WARN: EncryptionKey UID reference out of bounds in FilePlist.")
            elif encryption_key_obj:
                print(f"WARN: Unexpected EncryptionKey type in FilePlist: {type(encryption_key_obj)}")


            self.is_valid = True # Mark as successfully parsed

        except Exception as e:
            print(f"ERROR: Failed to parse FilePlist: {e}")
            self.is_valid = False


# --- Cryptographic Helpers (from google_iphone_dataprotection.py) ---

def _loopTLVBlocks(blob):
    i = 0
    while i + 8 <= len(blob):
        tag = blob[i:i+4]
        length = struct.unpack(">L", blob[i+4:i+8])[0]
        # Check for plausible length to avoid reading huge amounts of memory
        # if the data is corrupt. Adjust max length as needed.
        MAX_TLV_LEN = 1024 * 1024 # 1MB sanity check
        if length > MAX_TLV_LEN or i + 8 + length > len(blob):
            print(f"WARN: Invalid TLV length ({length} bytes) or exceeds blob size at offset {i}. Stopping parse.")
            break
        data = blob[i+8:i+8+length]
        yield (tag, data)
        i += 8 + length

def _unpack64bit(s):
    return struct.unpack(">Q", s)[0]

def _pack64bit(s):
    return struct.pack(">Q", s)

def _AESUnwrap(kek, wrapped):
    if not _CRYPTO_AVAILABLE:
        raise ImportError("pycryptodome is required for key unwrapping.")
    if len(wrapped) < 16 or len(wrapped) % 8 != 0:
        print(f"WARN: AESUnwrap input 'wrapped' has invalid length {len(wrapped)}. Must be multiple of 8 and >= 16.")
        return None # Invalid input length for AES Key Wrap

    C = []
    for i in range(len(wrapped)//8):
        C.append(_unpack64bit(wrapped[i * 8:i * 8 + 8]))
    n = len(C) - 1
    R = [0] * (n+1)
    # Default initial value A = 0xA6A6A6A6A6A6A6A6
    A = 0xA6A6A6A6A6A6A6A6

    for i in range(1, n+1):
        R[i] = C[i]

    cipher = Crypto.Cipher.AES.new(kek, Crypto.Cipher.AES.MODE_ECB)

    for j in reversed(range(0, 6)):
        for i in reversed(range(1, n+1)):
            # Prepare block for decryption: A XOR (n*j + i) | R[i]
            todec = _pack64bit(A ^ (n * j + i)) + _pack64bit(R[i])
            B = cipher.decrypt(todec)
            A = _unpack64bit(B[:8])
            R[i] = _unpack64bit(B[8:])

    # Check if the final A matches the expected initial value
    if A != 0xa6a6a6a6a6a6a6a6:
        # print(f"DEBUG: AESUnwrap failed integrity check. Final A: {A:#0{18}x}")
        return None # Integrity check failed

    # Concatenate the R[1] to R[n] blocks
    res = b"".join(map(_pack64bit, R[1:]))
    return res

def AESdecryptCBC(data, key, iv=b"\x00" * 16):
    if not _CRYPTO_AVAILABLE:
        raise ImportError("pycryptodome is required for AES decryption.")
    if len(data) == 0:
        return b"" # Handle empty input
    if len(data) % 16:
        print(f"WARN: AESdecryptCBC: data length {len(data)} not /16, padding or truncation might be needed by caller.")
        # Don't truncate here, let removePadding handle it if appropriate
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(data)
    return decrypted_data

def removePadding(data, blocksize=16):
    """Removes PKCS#7 padding."""
    if not data:
        return b""
    # The last byte indicates the number of padding bytes.
    padding_len = data[-1]
    # Padding length must be between 1 and blocksize, inclusive.
    # Also, all padding bytes must have the value of padding_len.
    if 1 <= padding_len <= blocksize:
        # Check if the padding bytes are correct
        if data.endswith(bytes([padding_len]) * padding_len):
            return data[:-padding_len]
        else:
            # print("WARN: Invalid padding bytes detected.")
            # This might happen if the data wasn't actually padded or decryption failed
            # Return the data as is, or raise an error, depending on expected behavior.
            # Returning as-is is often safer for potentially non-standard data.
            return data # Or raise ValueError('Invalid CBC padding bytes')
    else:
        # If padding_len is not in the valid range, assume no padding or bad data.
        # print(f"WARN: Invalid padding length byte ({padding_len}), assuming no padding.")
        return data # Or raise ValueError('Invalid CBC padding length')

class Keybag:
    """Parses and handles the iOS Keybag from Manifest.plist."""
    def __init__(self, data):
        if not _CRYPTO_AVAILABLE:
             raise ImportError("pycryptodome is required for Keybag operations.")
        self.type = None
        self.uuid = None
        self.wrap = None
        self.deviceKey = None # Seems unused in original code sample
        self.attrs = {}
        self.classKeys = {}
        self.KeyBagKeys = None  # Left for potential future use (DATASIGN blob)
        self.parseBinaryBlob(data)

    def parseBinaryBlob(self, data):
        currentClassKey = None
        try:
            for tag, tag_data in _loopTLVBlocks(data):
                # Handle integer values represented as 4 bytes
                if len(tag_data) == 4 and tag not in [b'UUID']: # UUIDs are raw bytes
                     try:
                         # Attempt to unpack as big-endian unsigned long
                         parsed_data = struct.unpack(">L", tag_data)[0]
                     except struct.error:
                         # If unpack fails, keep as bytes (might be other 4-byte data)
                         # print(f"WARN: Could not unpack 4-byte TLV tag {tag!r} as integer, keeping bytes.")
                         parsed_data = tag_data
                else:
                     parsed_data = tag_data

                if tag == b"TYPE":
                    self.type = parsed_data
                    # Original code had a check for type > 3, maintain if needed
                    # if self.type > 3:
                    #     print("WARN: Keybag type > 3 : %d" % self.type)
                elif tag == b"UUID" and self.uuid is None:
                    self.uuid = parsed_data # Keep UUID as bytes
                elif tag == b"WRAP" and self.wrap is None:
                     self.wrap = parsed_data # Should be integer after unpack
                elif tag == b"UUID": # Start of a new class key definition
                    if currentClassKey:
                        # Store the previously accumulated class key if CLAS tag was present
                        if b"CLAS" in currentClassKey:
                            self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey
                        else:
                            print(f"WARN: Skipping keybag entry with UUID {currentClassKey.get(b'UUID')} due to missing CLAS tag.")
                    # Start new class key dict
                    currentClassKey = {b"UUID": parsed_data} # Keep UUID as bytes
                elif tag in [b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"]:
                    if currentClassKey is not None:
                         currentClassKey[tag] = parsed_data
                    else:
                        print(f"WARN: Found tag {tag!r} outside of a class key definition.")
                # Store other top-level attributes like SALT, ITER, DPSL, DPIC etc.
                elif currentClassKey is None:
                     self.attrs[tag] = parsed_data
                else:
                     # Store unknown tags within the current class key
                     # print(f"DEBUG: Storing unknown tag {tag!r} in current class key.")
                     currentClassKey[tag] = parsed_data

            # Store the last processed class key after the loop finishes
            if currentClassKey and b"CLAS" in currentClassKey:
                 self.classKeys[currentClassKey[b"CLAS"]] = currentClassKey
            elif currentClassKey:
                 print(f"WARN: Skipping last keybag entry with UUID {currentClassKey.get(b'UUID')} due to missing CLAS tag.")

        except Exception as e:
            print(f"ERROR: Failed during Keybag TLV parsing: {e}")
            raise

        # Sanity check required attributes for password derivation
        for req_attr in [b"SALT", b"ITER", b"DPSL", b"DPIC"]:
            if req_attr not in self.attrs:
                 raise ValueError(f"Keybag unlock failed: Missing required attribute {req_attr!r}")


    def unlockWithPassphrase(self, passphrase):
        """Derives keys using the provided passphrase."""
        if not _CRYPTO_AVAILABLE:
            raise ImportError("pycryptodome is required for unlocking.")
        if not isinstance(passphrase, bytes):
            passphrase = passphrase.encode('utf-8')

        # Ensure required attributes are present (checked in parseBinaryBlob now)
        salt = self.attrs[b"SALT"]
        iterations = self.attrs[b"ITER"]
        dpsl = self.attrs[b"DPSL"] # Double Protection Salt
        dpic = self.attrs[b"DPIC"] # Double Protection Iteration Count

        if not isinstance(iterations, int) or not isinstance(dpic, int):
             raise TypeError("Keybag iterations (ITER, DPIC) must be integers.")

        # PBKDF2 computation (using fast implementation if available)
        # print(f"DEBUG: Deriving keys with ITER={iterations}, DPIC={dpic}, fastpbkdf2={'available' if _FASTPBKDF2_AVAILABLE else 'unavailable'}")
        try:
            passphrase_round1 = pbkdf2_hmac('sha256', passphrase, dpsl, dpic, 32)
            passphrase_key = pbkdf2_hmac('sha1', passphrase_round1, salt, iterations, 32)
        except Exception as e:
            print(f"ERROR: PBKDF2 key derivation failed: {e}")
            return False

        # print("DEBUG: Passphrase key derived.")
        # Unwrap class keys protected by the passphrase
        unlocked_any = False
        WRAP_PASSPHRASE = 2 # Flag indicating passphrase protection
        for class_id, classkey_dict in self.classKeys.items():
            if b"WPKY" not in classkey_dict:
                # print(f"DEBUG: Class {class_id} has no WPKY (Wrapped Key)")
                continue # No wrapped key to decrypt

            # Check if the WRAP flag indicates passphrase protection
            if isinstance(classkey_dict.get(b"WRAP"), int) and (classkey_dict[b"WRAP"] & WRAP_PASSPHRASE):
                # print(f"DEBUG: Attempting to unwrap key for class {class_id}")
                wrapped_key = classkey_dict[b"WPKY"]
                unwrapped_key = _AESUnwrap(passphrase_key, wrapped_key)
                if unwrapped_key is not None:
                    # print(f"DEBUG: Class {class_id} key unwrapped successfully.")
                    classkey_dict[b"KEY"] = unwrapped_key # Store the decrypted key
                    unlocked_any = True
                else:
                    # This is the critical failure point if the password is wrong
                    # print(f"DEBUG: Failed to unwrap key for class {class_id}. Incorrect passphrase?")
                    # Don't stop; maybe only some keys fail? But usually all or none.
                    # For robustness, maybe clear any potentially partially unwrapped keys if one fails?
                    # For now, we just return False if *any* passphrase-wrapped key fails.
                    # Clear any keys unwrapped so far if one fails?
                    for ck_dict in self.classKeys.values():
                        ck_dict.pop(b"KEY", None)
                    return False # Indicate failure
            # else:
                # print(f"DEBUG: Class {class_id} WRAP flag ({classkey_dict.get(b'WRAP')}) doesn't indicate passphrase protection.")

        # Return True if at least one key was expected to be unwrapped and was successful,
        # or if no keys were passphrase-protected in the first place.
        # A more robust check might be needed depending on keybag variations.
        # The original code returned False if *any* unwrap failed. Let's stick to that.
        # If we reached here without returning False, it means all keys needing unwrap succeeded.
        # Check if *any* key was actually unwrapped, otherwise maybe it's not password protected?
        # However, the presence of ITER/SALT implies password protection.
        # The check should be: if we attempted to unwrap any key, at least one must succeed.
        # The current logic returns False inside the loop on first failure, so if we exit the loop,
        # it means all attempts succeeded. We just need to be sure an attempt was made if expected.
        needs_unlock_count = sum(1 for ck in self.classKeys.values() if isinstance(ck.get(b"WRAP"), int) and (ck[b"WRAP"] & WRAP_PASSPHRASE))
        if needs_unlock_count > 0 and not unlocked_any:
             print("WARN: Keybag seems passphrase protected, but no keys were successfully unwrapped.")
             # This case should ideally be caught by the 'return False' inside the loop.
             return False

        # print("DEBUG: Keybag unlock successful.")
        return True # Success

    def unwrapKeyForClass(self, protection_class, persistent_key):
        """Unwraps a file-specific key using the class key."""
        if not _CRYPTO_AVAILABLE:
             raise ImportError("pycryptodome is required for key unwrapping.")
        if protection_class not in self.classKeys:
             raise ValueError(f"Protection class {protection_class} not found in Keybag.")

        classkey_dict = self.classKeys[protection_class]
        if b"KEY" not in classkey_dict:
             # This could happen if unlockWithPassphrase wasn't called or failed,
             # or if this specific class wasn't passphrase protected (unlikely if needed here)
             raise RuntimeError(f"Class key for class {protection_class} is not available (unlock failed or wasn't required?).")

        class_key = classkey_dict[b"KEY"]

        # Original code had a length check, seems reasonable
        # Common lengths are 0x28 (40 bytes) or sometimes different sizes.
        # AES key wrap RFC 3394 requires input multiple of 8 bytes, >= 16 bytes.
        # Let's relax the specific 0x28 check but keep the AES wrap constraints in mind.
        if len(persistent_key) < 16 or len(persistent_key) % 8 != 0:
             print(f"WARN: Persistent key for class {protection_class} has unusual length {len(persistent_key)}. AES unwrap might fail.")
             # raise ValueError(f"Invalid persistent key length: {len(persistent_key)}")

        unwrapped_key = _AESUnwrap(class_key, persistent_key)
        if unwrapped_key is None:
             # print(f"DEBUG: Failed to unwrap persistent key for class {protection_class}.")
             raise ValueError(f"Failed to unwrap persistent key for protection class {protection_class}.")

        return unwrapped_key

# --- Main Extractor Class (based on iphone_backup.py, enhanced) ---

class IosBackupExtractor:

    def __init__(self, *, backup_directory, passphrase=None):
        """
        Initialize access to an iOS backup, supporting both encrypted and
        unencrypted formats.

        :param backup_directory:
            The path to the specific backup directory on disk (e.g., containing
            Manifest.db and Manifest.plist).
            Common locations:
              - Windows (Standard): '%AppData%\\Apple Computer\\MobileSync\\Backup\\[device-hash]'
              - Windows (Store): '%UserProfile%\\Apple\\MobileSync\\Backup\\[device-hash]'
              - macOS: '~/Library/Application Support/MobileSync/Backup/[device-hash]'
        :param passphrase:
            Optional. The passphrase for an *encrypted* backup.
            If provided, the backup is assumed to be encrypted.
            If None, the backup is assumed to be unencrypted.
            Provide as string (UTF-8 encoded) or bytes.
        """
        self._backup_directory = os.path.expandvars(backup_directory)
        if not os.path.isdir(self._backup_directory):
            raise FileNotFoundError(f"Backup directory not found: {self._backup_directory}")

        self._passphrase = passphrase # Store passphrase bytes if provided
        if passphrase and not isinstance(passphrase, bytes):
            self._passphrase = passphrase.encode("utf-8")

        # Paths to key files
        self._manifest_plist_path = os.path.join(self._backup_directory, 'Manifest.plist')
        self._manifest_db_path = os.path.join(self._backup_directory, 'Manifest.db')

        # State variables
        self._is_encrypted = False
        self._manifest_plist = None
        self._keybag = None
        self._unlocked = False # For encrypted backups
        self._temporary_folder = None # Only created if decrypting Manifest.db
        self._temp_decrypted_manifest_db_path = None
        self._manifest_db_conn = None # Connection to either original or temp DB

        # Determine if encrypted by checking Manifest.plist
        self._check_encryption_status()

        if self._is_encrypted and not _CRYPTO_AVAILABLE:
             raise ImportError("Backup is encrypted, but 'pycryptodome' package is not installed.")
        if self._is_encrypted and self._passphrase is None:
            raise ValueError("Backup is encrypted, but no passphrase was provided.")

    def _check_encryption_status(self):
        """Checks Manifest.plist to determine if the backup is encrypted."""
        if not os.path.exists(self._manifest_plist_path):
            # Older/corrupt backups might lack Manifest.plist, assume unencrypted if Manifest.db exists?
             if os.path.exists(self._manifest_db_path):
                 print("WARN: Manifest.plist not found, assuming unencrypted backup.")
                 self._is_encrypted = False
                 return
             else:
                raise FileNotFoundError(f"Manifest.plist and Manifest.db not found in {self._backup_directory}")

        try:
            with open(self._manifest_plist_path, 'rb') as f:
                self._manifest_plist = plistlib.load(f)

            # Encryption indicated by presence of BackupKeyBag and IsEncrypted flag
            if self._manifest_plist.get('IsEncrypted', False) and 'BackupKeyBag' in self._manifest_plist:
                self._is_encrypted = True
                # print("DEBUG: Backup identified as encrypted.")
            else:
                self._is_encrypted = False
                # print("DEBUG: Backup identified as unencrypted.")

        except Exception as e:
            print(f"ERROR: Failed to read or parse Manifest.plist: {e}")
            # Decide on fallback: maybe assume unencrypted if DB exists?
            if os.path.exists(self._manifest_db_path):
                print("WARN: Could not parse Manifest.plist, assuming unencrypted backup.")
                self._is_encrypted = False
            else:
                raise RuntimeError("Failed to parse Manifest.plist and Manifest.db not found.") from e


    def is_encrypted(self):
        """Returns True if the backup is detected as encrypted, False otherwise."""
        return self._is_encrypted

    def _read_and_unlock_keybag(self):
        """Loads and unlocks the Keybag (only for encrypted backups)."""
        if not self._is_encrypted:
            # Should not be called for unencrypted backups
            raise RuntimeError("Cannot unlock keybag for unencrypted backup.")
        if self._unlocked:
            return True # Already unlocked

        if not self._manifest_plist: # Should have been loaded by _check_encryption_status
             raise RuntimeError("Manifest.plist not loaded.")
        if not self._passphrase:
             raise ValueError("Passphrase required but not available for unlocking.")

        try:
            # print("DEBUG: Initializing Keybag...")
            self._keybag = Keybag(self._manifest_plist['BackupKeyBag'])
            # print("DEBUG: Attempting Keybag unlock...")
            self._unlocked = self._keybag.unlockWithPassphrase(self._passphrase)

            if not self._unlocked:
                raise ValueError("Failed to decrypt keys: incorrect passphrase?")

            # print("DEBUG: Keybag unlocked successfully.")
            # Clear passphrase from memory now that keys are derived
            self._passphrase = None
            return True

        except Exception as e:
            self._unlocked = False # Ensure state is correct on failure
            # Don't clear passphrase on failure, user might retry
            print(f"ERROR: Keybag unlock failed: {e}")
            # Re-raise specific errors or a generic one
            if isinstance(e, (ValueError, ImportError, TypeError, RuntimeError)):
                 raise # Propagate known error types
            else:
                 raise RuntimeError("An unexpected error occurred during keybag unlock.") from e


    def _decrypt_manifest_db_file(self):
        """Decrypts Manifest.db to a temporary file (only for encrypted backups)."""
        if not self._is_encrypted:
            raise RuntimeError("Cannot decrypt Manifest.db for unencrypted backup.")
        if self._temp_decrypted_manifest_db_path and os.path.exists(self._temp_decrypted_manifest_db_path):
             # print("DEBUG: Using existing decrypted Manifest.db temp file.")
             return # Already decrypted

        # Ensure keybag is unlocked
        self._read_and_unlock_keybag()

        # Create temporary directory if it doesn't exist
        if self._temporary_folder is None:
             self._temporary_folder = tempfile.mkdtemp(prefix="ios_backup_")
             self._temp_decrypted_manifest_db_path = os.path.join(self._temporary_folder, 'Manifest.db')
             # print(f"DEBUG: Created temporary folder: {self._temporary_folder}")

        # Decrypt the Manifest.db index database
        if 'ManifestKey' not in self._manifest_plist:
             raise RuntimeError("ManifestKey missing from Manifest.plist (required for Manifest.db decryption).")

        manifest_key_data = self._manifest_plist['ManifestKey'] # This is usually 4 bytes class + 40 bytes key
        if len(manifest_key_data) != 44:
             print(f"WARN: Unexpected ManifestKey length: {len(manifest_key_data)} bytes (expected 44).")
             # Attempt to proceed, assuming first 4 bytes are class, rest is key
             if len(manifest_key_data) < 5:
                 raise ValueError("ManifestKey too short.")

        manifest_class = struct.unpack('<l', manifest_key_data[:4])[0] # Little-endian signed long
        manifest_key = manifest_key_data[4:]
        # print(f"DEBUG: Manifest class: {manifest_class}, Key length: {len(manifest_key)}")

        try:
             # print("DEBUG: Unwrapping Manifest.db key...")
             key = self._keybag.unwrapKeyForClass(manifest_class, manifest_key)
             # print("DEBUG: Manifest.db key unwrapped.")
             if not key: # Should be caught by exception in unwrapKeyForClass now
                  raise RuntimeError("Failed to unwrap Manifest.db key (returned None).")

             # print("DEBUG: Reading encrypted Manifest.db...")
             with open(self._manifest_db_path, 'rb') as encrypted_db_filehandle:
                 encrypted_db = encrypted_db_filehandle.read()

             # print("DEBUG: Decrypting Manifest.db...")
             decrypted_data = AESdecryptCBC(encrypted_db, key)
             # print("DEBUG: Removing padding from Manifest.db...")
             # Manifest.db should be a standard SQLite file, likely requires padding removal
             sqlite_magic = b"SQLite format 3\x00"
             padded_db = decrypted_data
             decrypted_data = removePadding(padded_db) # Use padding removal

             # Simple sanity check for SQLite header
             if not decrypted_data.startswith(sqlite_magic):
                  # Try without padding removal if header check fails? Sometimes padding isn't standard.
                  if padded_db.startswith(sqlite_magic):
                      print("WARN: Decrypted Manifest.db didn't start with SQLite magic after padding removal, but did before. Using un-padded data.")
                      decrypted_data = padded_db
                  else:
                      raise ValueError("Decrypted Manifest.db does not start with SQLite magic header.")

             # print("DEBUG: Writing decrypted Manifest.db to temp file...")
             with open(self._temp_decrypted_manifest_db_path, 'wb') as decrypted_db_filehandle:
                 decrypted_db_filehandle.write(decrypted_data)
             # print(f"DEBUG: Decrypted Manifest.db written to {self._temp_decrypted_manifest_db_path}")

        except Exception as e:
            print(f"ERROR: Failed to decrypt Manifest.db: {e}")
            # Clean up temp file if created partially
            if self._temp_decrypted_manifest_db_path and os.path.exists(self._temp_decrypted_manifest_db_path):
                try: os.remove(self._temp_decrypted_manifest_db_path)
                except OSError: pass
            self._temp_decrypted_manifest_db_path = None # Reset path
            raise RuntimeError("Manifest.db decryption failed.") from e


    def _get_manifest_db_connection(self):
        """Returns a SQLite connection to the (potentially decrypted) Manifest.db."""
        if self._manifest_db_conn:
            # Test connection? SQLite handles this reasonably well.
            try:
                 # Simple query to check if connection is alive
                 self._manifest_db_conn.execute("SELECT count(*) FROM sqlite_master;").fetchone()
                 return self._manifest_db_conn
            except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                 print("WARN: Stale Manifest DB connection detected, reopening.")
                 try: self._manifest_db_conn.close()
                 except Exception: pass
                 self._manifest_db_conn = None # Force reconnect

        db_path_to_open = None
        if self._is_encrypted:
            # Ensure Manifest.db is decrypted
            self._decrypt_manifest_db_file() # Ensures temp file exists
            if not self._temp_decrypted_manifest_db_path or not os.path.exists(self._temp_decrypted_manifest_db_path):
                 raise RuntimeError("Decrypted Manifest.db temporary file not found.")
            db_path_to_open = self._temp_decrypted_manifest_db_path
            # print(f"DEBUG: Connecting to temporary decrypted DB: {db_path_to_open}")
        else:
            # Use original Manifest.db
            if not os.path.exists(self._manifest_db_path):
                 raise FileNotFoundError(f"Manifest.db not found at {self._manifest_db_path}")
            db_path_to_open = self._manifest_db_path
            # print(f"DEBUG: Connecting to original DB: {db_path_to_open}")

        try:
             # Connect in read-only mode if possible? Useful for safety.
             # URI mode allows specifying 'mode=ro'
             db_uri = f"file:{db_path_to_open}?mode=ro"
             self._manifest_db_conn = sqlite3.connect(db_uri, uri=True)
             # print("DEBUG: DB Connection successful (read-only).")
             # Check it has the expected table structure
             cur = self._manifest_db_conn.cursor()
             cur.execute("SELECT count(*) FROM Files;")
             file_count = cur.fetchone()[0]
             cur.close()
             # print(f"DEBUG: Manifest DB contains {file_count} file records.")
             if self._is_encrypted and file_count == 0:
                  # Decryption might have failed silently or DB is empty
                  print("WARN: Decrypted Manifest.db appears empty.")
             return self._manifest_db_conn
        except sqlite3.Error as e:
             print(f"ERROR: Failed to connect to or query Manifest database at {db_path_to_open}: {e}")
             # Clean up connection object if partially created
             if self._manifest_db_conn:
                 try: self._manifest_db_conn.close()
                 except Exception: pass
             self._manifest_db_conn = None
             # For encrypted backups, maybe the decryption failed?
             if self._is_encrypted:
                  raise ConnectionError("Failed to open decrypted Manifest.db. Decryption may have failed or file is corrupt.") from e
             else:
                  raise ConnectionError("Failed to open Manifest.db. File may be corrupt.") from e


    @contextmanager
    def manifest_db_cursor(self):
        """Provides a temporary read-only cursor to the Manifest database."""
        conn = self._get_manifest_db_connection()
        cursor = None
        try:
            cursor = conn.cursor()
            yield cursor
        finally:
            if cursor:
                try: cursor.close()
                except sqlite3.Error: pass # Ignore errors closing cursor

    def _file_metadata_from_manifest(self, relative_path=None, domain_like=None, file_id_sha1=None):
        """Fetches file metadata (incl. bplist) from Manifest.db."""
        if not relative_path and not file_id_sha1:
             raise ValueError("Either relative_path or file_id_sha1 must be provided.")
        if relative_path and file_id_sha1:
             print("WARN: Both relative_path and file_id_sha1 provided, using file_id_sha1 for lookup.")
             relative_path = None # Prioritize fileID

        sql_query = """
            SELECT fileID, domain, relativePath, flags, file
            FROM Files
            WHERE """
        params = []

        if file_id_sha1:
             sql_query += " fileID = ? "
             params.append(file_id_sha1)
        else: # Use relative_path and domain_like
             sql_query += " relativePath = ? "
             params.append(relative_path)
             if domain_like:
                 sql_query += " AND domain LIKE ? "
                 params.append(domain_like)
             else:
                 # Match any domain if not specified, but maybe warn if multiple matches?
                 # Or default to HomeDomain? Let's match any for now.
                 pass

        # Filter for actual files (flags=1) vs directories (flags=2) etc.
        sql_query += " AND flags = 1 "

        # Order preference? Maybe domain?
        sql_query += " ORDER BY domain, relativePath LIMIT 1;" # Limit 1 for single file methods

        # print(f"DEBUG: Manifest Query: {sql_query} PARAMS: {params}")
        try:
            with self.manifest_db_cursor() as cur:
                cur.execute(sql_query, params)
                result = cur.fetchone()
        except sqlite3.Error as e:
            raise RuntimeError("Error querying Manifest database!") from e

        if not result:
            criteria = f"fileID '{file_id_sha1}'" if file_id_sha1 else f"path '{relative_path}' (domain like '{domain_like or '%'}')"
            raise FileNotFoundError(f"File not found in Manifest database matching criteria: {criteria}")

        file_id_res, domain_res, rel_path_res, flags_res, file_bplist = result
        # print(f"DEBUG: Found file: ID={file_id_res}, Domain={domain_res}, Path={rel_path_res}, Flags={flags_res}")

        # Parse the bplist data
        file_plist = FilePlist(file_bplist)
        if not file_plist.is_valid:
             raise ValueError(f"Failed to parse file metadata PList for fileID {file_id_res}")

        return file_id_res, domain_res, rel_path_res, file_plist


    def _get_backup_filepath(self, file_id):
        """Constructs the path to the file within the backup directory structure."""
        # Files are stored in subdirectories named with the first two chars of fileID
        if len(file_id) < 2:
             raise ValueError(f"Invalid fileID format: {file_id}")
        subdir = file_id[:2]
        return os.path.join(self._backup_directory, subdir, file_id)


    def _extract_or_copy_file(self, *, file_id, file_plist, output_filepath):
        """Internal helper to handle both encrypted decryption and unencrypted copy."""
        source_filepath = self._get_backup_filepath(file_id)
        if not os.path.exists(source_filepath):
            raise FileNotFoundError(f"Backup file data not found at {source_filepath}")

        # Ensure output directory exists
        output_directory = os.path.dirname(output_filepath)
        if output_directory:
            os.makedirs(output_directory, exist_ok=True)

        file_is_encrypted = self._is_encrypted and file_plist.encryption_key is not None

        try:
            if file_is_encrypted:
                # Decrypt the file
                # print(f"DEBUG: Decrypting {file_id} to {output_filepath}")
                self._read_and_unlock_keybag() # Ensure unlocked
                inner_key = self._keybag.unwrapKeyForClass(file_plist.protection_class, file_plist.encryption_key)
                if not inner_key: # Should be caught by exception now
                    raise RuntimeError(f"Failed to unwrap key for file {file_id}")

                # Use chunked decryption for potentially large files
                aes_decrypt_chunked(
                    in_filename=source_filepath,
                    out_filepath=output_filepath,
                    key=inner_key,
                    file_plist=file_plist # Pass plist for size check and mtime
                )

            else:
                # Copy the file directly (unencrypted)
                # print(f"DEBUG: Copying {file_id} to {output_filepath}")
                shutil.copy2(source_filepath, output_filepath) # copy2 preserves metadata like mtime

                # Verify size after copy for unencrypted files
                copied_size = os.path.getsize(output_filepath)
                if copied_size != file_plist.filesize:
                     print(f"WARN: Copied file size mismatch for '{output_filepath}'. Expected {file_plist.filesize}, got {copied_size}.")

            # Set modification time from plist data if available (copy2 might do this, but explicit is safer)
            if file_plist.mtime:
                 try:
                     # Convert datetime object to timestamp if needed
                     if hasattr(file_plist.mtime, 'timestamp'):
                          mtime_ts = file_plist.mtime.timestamp()
                          os.utime(output_filepath, times=(mtime_ts, mtime_ts))
                     else:
                          # Assume it's already a suitable timestamp number? Risky.
                          # print(f"WARN: Unknown mtime format: {type(file_plist.mtime)}, cannot set file time.")
                          pass # Skip setting time if format is unexpected
                 except Exception as time_e:
                     print(f"WARN: Failed to set modification time for {output_filepath}: {time_e}")

        except Exception as e:
            print(f"ERROR: Failed to {'decrypt' if file_is_encrypted else 'copy'} file {file_id} to {output_filepath}: {e}")
            # Attempt to remove partially written file
            if os.path.exists(output_filepath):
                try: os.remove(output_filepath)
                except OSError: pass
            raise # Re-raise the exception


    def test_backup_access(self):
        """
        Tests if the backup is accessible.
        For encrypted backups, attempts to unlock the keybag.
        For unencrypted backups, attempts to connect to Manifest.db.
        """
        print(f"Testing access for backup at: {self._backup_directory}")
        print(f"Detected as: {'Encrypted' if self._is_encrypted else 'Unencrypted'}")
        try:
            if self._is_encrypted:
                print("Attempting keybag unlock...")
                if not self._passphrase:
                    print("ERROR: Encrypted backup requires a passphrase for testing.")
                    return False
                unlocked = self._read_and_unlock_keybag()
                if unlocked:
                     print("Keybag unlock SUCCESSFUL.")
                     # Optionally, test Manifest.db decryption as well?
                     try:
                         print("Attempting Manifest.db connection (requires decryption)...")
                         conn = self._get_manifest_db_connection()
                         # We don't need to do anything with conn, just getting it is the test
                         print("Manifest.db access SUCCESSFUL.")
                         return True
                     except Exception as db_e:
                         print(f"Manifest.db access FAILED: {db_e}")
                         return False
                else:
                     # _read_and_unlock_keybag now raises on failure
                     # This part might not be reachable if exceptions are used properly
                     print("Keybag unlock FAILED. Incorrect passphrase?")
                     return False
            else:
                # Unencrypted: just try connecting to the DB
                print("Attempting Manifest.db connection...")
                conn = self._get_manifest_db_connection()
                # Check if connection succeeded (implicit in not raising error)
                print("Manifest.db access SUCCESSFUL.")
                return True
        except Exception as e:
            print(f"Backup access test FAILED: {e}")
            return False


    def save_manifest_file(self, output_filename):
        """
        Saves a copy of the Manifest SQLite database.
        For encrypted backups, saves the decrypted version.
        For unencrypted backups, saves the original version.
        """
        # Ensure output directory exists
        output_directory = os.path.dirname(output_filename)
        if output_directory:
            os.makedirs(output_directory, exist_ok=True)

        source_db_path = None
        if self._is_encrypted:
            print("Ensuring Manifest.db is decrypted...")
            self._decrypt_manifest_db_file() # Creates the temp file
            if not self._temp_decrypted_manifest_db_path or not os.path.exists(self._temp_decrypted_manifest_db_path):
                raise RuntimeError("Could not get decrypted Manifest.db path.")
            source_db_path = self._temp_decrypted_manifest_db_path
            print(f"Copying decrypted Manifest.db to {output_filename}")
        else:
            if not os.path.exists(self._manifest_db_path):
                 raise FileNotFoundError(f"Original Manifest.db not found at {self._manifest_db_path}")
            source_db_path = self._manifest_db_path
            print(f"Copying original Manifest.db to {output_filename}")

        try:
            shutil.copy2(source_db_path, output_filename) # copy2 preserves metadata
            print("Manifest.db saved successfully.")
        except Exception as e:
            print(f"ERROR: Failed to save Manifest.db: {e}")
            raise


    def extract_file_as_bytes(self, *, relative_path=None, domain_like=None, file_id_sha1=None):
        """
        Extracts a single file and returns its contents as bytes.
        Handles decryption automatically if the backup is encrypted.

        NOTE: This loads the entire file into memory. Use extract_file()
        for large files.

        :param relative_path: iOS 'relativePath' (e.g., from RelativePath class).
        :param domain_like: Optional iOS 'domain' with SQL wildcards (e.g., from DomainLike).
                            Use if relative_path is not unique.
        :param file_id_sha1: Optional iOS 'fileID' (SHA1 hash). Takes precedence over path/domain.

        :return: bytes of the file content.
        :raises FileNotFoundError: If the file is not found in the Manifest.db.
        :raises ValueError: If metadata or keys are invalid.
        :raises RuntimeError: For keybag or decryption errors.
        """
        file_id, _, _, file_plist = self._file_metadata_from_manifest(
            relative_path=relative_path, domain_like=domain_like, file_id_sha1=file_id_sha1
        )

        source_filepath = self._get_backup_filepath(file_id)
        if not os.path.exists(source_filepath):
             raise FileNotFoundError(f"Backup file data not found at {source_filepath} for fileID {file_id}")

        file_is_encrypted = self._is_encrypted and file_plist.encryption_key is not None

        try:
            with open(source_filepath, 'rb') as f_in:
                file_data = f_in.read()

            if file_is_encrypted:
                # print(f"DEBUG: Decrypting file {file_id} into memory.")
                self._read_and_unlock_keybag()
                inner_key = self._keybag.unwrapKeyForClass(file_plist.protection_class, file_plist.encryption_key)
                if not inner_key: raise RuntimeError(f"Failed to unwrap key for file {file_id}")

                decrypted_data = AESdecryptCBC(file_data, inner_key)
                file_bytes = removePadding(decrypted_data)

                # Verify size after decryption
                if len(file_bytes) != file_plist.filesize:
                     print(f"WARN: Decrypted size mismatch for file {file_id}. Expected {file_plist.filesize}, got {len(file_bytes)}.")
                     # Decide whether to raise or return potentially corrupt data. Let's return it with warning.
                     # raise AssertionError(f"Expected file size {file_plist.filesize}, decrypted {len(file_bytes)} bytes!")

                return file_bytes
            else:
                # Unencrypted, just return the data read
                # Verify size
                if len(file_data) != file_plist.filesize:
                     print(f"WARN: Unencrypted file size mismatch for {file_id}. Expected {file_plist.filesize}, got {len(file_data)}.")
                return file_data

        except Exception as e:
            print(f"ERROR: Failed to extract file {file_id} as bytes: {e}")
            raise


    def extract_file(self, *, output_filename, relative_path=None, domain_like=None, file_id_sha1=None):
        """
        Extracts a single file and saves it to disk.
        Handles decryption automatically if the backup is encrypted.
        Recommended for larger files over extract_file_as_bytes().

        :param output_filename: Path to save the extracted file.
        :param relative_path: iOS 'relativePath' (e.g., from RelativePath class).
        :param domain_like: Optional iOS 'domain' with SQL wildcards (e.g., from DomainLike).
                            Use if relative_path is not unique.
        :param file_id_sha1: Optional iOS 'fileID' (SHA1 hash). Takes precedence over path/domain.

        :raises FileNotFoundError: If the file is not found in Manifest.db or backup storage.
        :raises ValueError: If metadata or keys are invalid.
        :raises RuntimeError: For keybag or decryption errors.
        """
        file_id, _, _, file_plist = self._file_metadata_from_manifest(
            relative_path=relative_path, domain_like=domain_like, file_id_sha1=file_id_sha1
        )

        # Use the unified extraction/copy helper
        self._extract_or_copy_file(
            file_id=file_id,
            file_plist=file_plist,
            output_filepath=output_filename
        )
        # print(f"DEBUG: Successfully extracted {file_id} to {output_filename}")


    def extract_files(self, *, output_folder, relative_paths_like=None, domain_like=None,
                      preserve_folders=False, domain_subfolders=False, incremental=False,
                      filter_callback=None):
        """
        Extracts multiple files matching criteria and saves them to a folder.
        Handles decryption automatically. Uses chunked decryption/copying.

        :param output_folder: Directory to save extracted files.
        :param relative_paths_like: Optional SQL LIKE pattern for 'relativePath'.
        :param domain_like: Optional SQL LIKE pattern for 'domain'.
            *At least one* of relative_paths_like or domain_like must be specified.
        :param preserve_folders: If True, recreate the relativePath folder structure
                                 within the output folder (or domain subfolder).
        :param domain_subfolders: If True, create subfolders named after the 'domain'
                                  within the output folder.
        :param incremental: If True, skip extraction if a file with the same name
                            already exists in the target path and its modification
                            time is >= the backup file's modification time.
        :param filter_callback: Optional function called before extracting each file.
                                Receives kwargs: `n`, `total_files`, `file_id`,
                                `domain`, `relative_path`, `file_plist`.
                                If it returns False, the file is skipped.
                                Example signature: `def my_filter(**kwargs): return True`

        :return: Number of files successfully extracted (or skipped by incremental).
        :raises ValueError: If neither relative_paths_like nor domain_like is given.
        :raises RuntimeError: For database query or file extraction errors.
        """
        # Argument validation
        if relative_paths_like is None and domain_like is None:
            raise ValueError("At least one of 'relative_paths_like' or 'domain_like' must be specified!")
        rel_path_pattern = relative_paths_like if relative_paths_like is not None else "%"
        domain_pattern = domain_like if domain_like is not None else "%"

        _include_fn = filter_callback if callable(filter_callback) else (lambda **kwargs: True)

        # Query Manifest.db for matching files
        query = """
            SELECT fileID, domain, relativePath, flags, file
            FROM Files
            WHERE relativePath LIKE ?
              AND domain LIKE ?
              AND flags = 1
            ORDER BY domain, relativePath;
        """
        params = (rel_path_pattern, domain_pattern)
        # print(f"DEBUG: Querying files with Path LIKE '{rel_path_pattern}', Domain LIKE '{domain_pattern}'")

        try:
            with self.manifest_db_cursor() as cur:
                cur.execute(query, params)
                results = cur.fetchall()
        except sqlite3.Error as e:
            raise RuntimeError("Error querying Manifest database for multiple files!") from e

        # Ensure output destination exists
        os.makedirs(output_folder, exist_ok=True)

        n_extracted = 0
        total_files = len(results)
        print(f"Found {total_files} matching file(s) in Manifest.db.")

        for n, (file_id, domain, relative_path, flags, file_bplist) in enumerate(results):
            try:
                # Parse the metadata plist
                file_plist = FilePlist(file_bplist)
                if not file_plist.is_valid:
                     print(f"WARN: Skipping fileID {file_id} (path: {relative_path}) due to invalid metadata PList.")
                     continue

                # Apply user filter function
                filter_args = {
                    "n": n, "total_files": total_files, "file_id": file_id,
                    "domain": domain, "relative_path": relative_path,
                    "file_plist": file_plist # Pass the parsed object
                }
                if not _include_fn(**filter_args):
                    # print(f"DEBUG: Skipping file {file_id} due to filter_callback.")
                    continue

                # Determine output path structure
                output_path_parts = [output_folder]
                if domain_subfolders:
                    # Sanitize domain name for use as folder name (optional but recommended)
                    safe_domain = domain.replace(":", "_").replace("/", "_").replace("\\", "_")
                    output_path_parts.append(safe_domain)

                path_inside_output = []
                if preserve_folders:
                    path_inside_output.append(os.path.dirname(relative_path))
                # Ensure filename is clean (though relativePath usually is)
                filename = os.path.basename(relative_path)
                if not filename: # Handle cases like 'Library/' which might match '%'
                     print(f"WARN: Skipping fileID {file_id} with empty filename derived from relativePath '{relative_path}'.")
                     continue
                path_inside_output.append(filename)

                # Join parts carefully, avoiding issues with absolute paths in relative_path
                relative_output_path = os.path.join(*path_inside_output)
                # Ensure the path is treated as relative before joining to the base parts
                relative_output_path = os.path.normpath(relative_output_path).lstrip(os.sep)

                output_filepath = os.path.join(*output_path_parts, relative_output_path)

                # Incremental check
                if incremental and os.path.exists(output_filepath):
                     try:
                         existing_mtime = os.path.getmtime(output_filepath)
                         backup_mtime_ts = None
                         if file_plist.mtime and hasattr(file_plist.mtime, 'timestamp'):
                             backup_mtime_ts = file_plist.mtime.timestamp()

                         if backup_mtime_ts is not None and backup_mtime_ts <= existing_mtime:
                             # print(f"DEBUG: Skipping existing file (incremental): {output_filepath}")
                             n_extracted += 1 # Count skipped files towards total for progress indication? Or only successful writes? Let's count skips too.
                             continue
                     except Exception as inc_e:
                         print(f"WARN: Incremental check failed for {output_filepath}: {inc_e}. Will attempt extraction.")


                # Extract/Copy the file using the helper method
                print(f"[{n+1}/{total_files}] Extracting: {relative_path} ({domain}) -> {output_filepath}")
                self._extract_or_copy_file(
                    file_id=file_id,
                    file_plist=file_plist,
                    output_filepath=output_filepath
                )
                n_extracted += 1

            except FileNotFoundError as fnf_e:
                 print(f"WARN: [{n+1}/{total_files}] Skipping file {file_id} (path: {relative_path}): Backup data not found. {fnf_e}")
                 continue # Skip to next file
            except (ValueError, RuntimeError, sqlite3.Error, OSError, IOError) as e:
                 print(f"ERROR: [{n+1}/{total_files}] Failed to extract file {file_id} (path: {relative_path}): {e}")
                 # Optionally: stop processing, or continue with next file? Continue is often better.
                 continue # Skip to next file
            except Exception as e:
                 print(f"FATAL ERROR: [{n+1}/{total_files}] Unexpected error extracting file {file_id} (path: {relative_path}): {e}")
                 raise # Re-raise unexpected errors

        print(f"Extraction complete. {n_extracted} file(s) processed.")
        return n_extracted

    def _cleanup(self):
        """Closes DB connection and removes temporary files."""
        # print("DEBUG: Cleaning up resources...")
        if self._manifest_db_conn:
            try:
                self._manifest_db_conn.close()
                # print("DEBUG: Manifest DB connection closed.")
            except Exception as e:
                print(f"WARN: Error closing Manifest DB connection: {e}")
            self._manifest_db_conn = None

        if self._temporary_folder and os.path.exists(self._temporary_folder):
            try:
                shutil.rmtree(self._temporary_folder)
                # print(f"DEBUG: Removed temporary folder: {self._temporary_folder}")
            except Exception as e:
                print(f"WARN: Failed to remove temporary folder '{self._temporary_folder}': {e}")
                print("      You may need to remove it manually.")
            self._temporary_folder = None
            self._temp_decrypted_manifest_db_path = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - performs cleanup."""
        self._cleanup()

    def __del__(self):
        """Destructor - performs cleanup."""
        self._cleanup()

# --- Utility Functions (from utils.py, potentially modified) ---

def aes_decrypt_chunked(*, in_filename, file_plist, key, out_filepath):
    """
    Decrypts a backup file chunk by chunk using AES CBC.
    Verifies size and sets modification time.
    """
    if not _CRYPTO_AVAILABLE:
        raise ImportError("pycryptodome is required for AES decryption.")

    # print(f"DEBUG: aes_decrypt_chunked: In='{in_filename}', Out='{out_filepath}', Key=<{len(key)} bytes>, Filesize={file_plist.filesize}")
    # Initialise AES cipher: IV is always zeros for backup files? Based on original code.
    iv = b"\x00" * _CBC_BLOCK_SIZE
    aes_cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv=iv)

    try:
        with open(in_filename, 'rb') as enc_filehandle, open(out_filepath, 'wb') as dec_filehandle:
            bytes_written = 0
            while True:
                enc_data = enc_filehandle.read(_CHUNK_SIZE)
                if not enc_data:
                    break # End of file

                # Decrypt chunk
                dec_data = aes_cipher.decrypt(enc_data)

                # Handle padding ONLY on the *last* expected chunk
                # We need to know the total expected *decrypted* size (file_plist.filesize)
                # and compare bytes_written + len(dec_data) to it.

                # Calculate potential total size if this chunk is fully written
                potential_total = bytes_written + len(dec_data)

                if potential_total >= file_plist.filesize:
                    # This chunk contains the end of the actual file data
                    # Calculate how much data is needed from this chunk
                    needed_from_this_chunk = file_plist.filesize - bytes_written
                    if needed_from_this_chunk < 0: needed_from_this_chunk = 0 # Should not happen

                    # Take only the necessary bytes
                    final_data = dec_data[:needed_from_this_chunk]
                    dec_filehandle.write(final_data)
                    bytes_written += len(final_data)
                    # print(f"DEBUG: Last chunk processed. Wrote {len(final_data)} bytes. Total: {bytes_written}")
                    break # We have written exactly filesize bytes
                else:
                    # This is not the last chunk, write all decrypted data
                    dec_filehandle.write(dec_data)
                    bytes_written += len(dec_data)
                    # print(f"DEBUG: Wrote chunk of {len(dec_data)} bytes. Total: {bytes_written}")


            # Final size verification
            dec_filehandle.flush() # Ensure buffer is written
            final_size = dec_filehandle.tell()
            if final_size != file_plist.filesize:
                 print(f"WARN: Decrypted file size mismatch for '{out_filepath}'. Expected {file_plist.filesize}, wrote {final_size}.")
                 # This indicates a problem with decryption or padding, or the plist size info.

    except Exception as e:
        print(f"ERROR: AES decryption failed for {in_filename}: {e}")
        # Clean up potentially corrupt output file
        if os.path.exists(out_filepath):
            try: os.remove(out_filepath)
            except OSError: pass
        raise # Re-raise the error

    # Set modification time (already handled in _extract_or_copy_file which calls this)
    # But we can leave it here as well for direct callers, though it requires file_plist
    # if file_plist.mtime:
    #     try:
    #         if hasattr(file_plist.mtime, 'timestamp'):
    #             mtime_ts = file_plist.mtime.timestamp()
    #             os.utime(out_filepath, times=(mtime_ts, mtime_ts))
    #     except Exception as time_e:
    #         print(f"WARN: Failed to set modification time for {out_filepath}: {time_e}")


# --- Example Usage ---

if __name__ == '__main__':
    import argparse
    import getpass

    parser = argparse.ArgumentParser(description="Extract files from an iOS backup (encrypted or unencrypted).")
    parser.add_argument("backup_dir", help="Path to the iOS backup directory (containing Manifest.db/plist).")
    parser.add_argument("output_dir", help="Directory where extracted files will be saved.")
    parser.add_argument("-p", "--password", help="Password for encrypted backup (will prompt if needed and not provided).", default=None)
    parser.add_argument("--relpath", help="SQL LIKE pattern for relativePath (e.g., 'Library/SMS/sms.db', 'Media/DCIM/%').", default=None)
    parser.add_argument("--domain", help="SQL LIKE pattern for domain (e.g., 'HomeDomain', 'CameraRollDomain', 'AppDomainGroup-group.net.whatsapp.WhatsApp.shared').", default=None)
    parser.add_argument("--fileid", help="Specific fileID (SHA1 hash) to extract.", default=None)
    parser.add_argument("--save-manifest", help="Also save a copy of the (decrypted) Manifest.db to this file path.", default=None)
    parser.add_argument("--preserve-folders", help="Recreate relativePath folder structure in output.", action='store_true')
    parser.add_argument("--domain-folders", help="Create domain subfolders in output.", action='store_true')
    parser.add_argument("--incremental", help="Skip extraction if output file exists and is not older.", action='store_true')
    parser.add_argument("--test", help="Only test backup access and password, do not extract.", action='store_true')

    args = parser.parse_args()

    # --- Input Validation ---
    if not os.path.isdir(args.backup_dir):
        print(f"ERROR: Backup directory not found: {args.backup_dir}")
        exit(1)

    if not args.test and not args.fileid and not args.relpath and not args.domain and not args.save_manifest:
         parser.error("You must specify criteria for extraction (--fileid, --relpath, --domain) or --save-manifest, unless using --test.")

    if args.fileid and (args.relpath or args.domain):
        print("WARN: --fileid provided, ignoring --relpath and --domain.")
        args.relpath = None
        args.domain = None

    # --- Initialize Extractor ---
    backup_password = args.password
    extractor = None # Define before try block

    try:
        # Check encryption status *before* prompting for password if not provided
        temp_checker = IosBackupExtractor(backup_directory=args.backup_dir)
        is_enc = temp_checker.is_encrypted()
        del temp_checker # Don't need it anymore

        if is_enc and not backup_password:
            print("Backup appears to be encrypted.")
            try:
                backup_password = getpass.getpass("Enter backup password: ")
            except EOFError:
                 print("\nERROR: Could not read password from prompt.")
                 exit(1)
            if not backup_password:
                print("ERROR: Password required for encrypted backup.")
                exit(1)

        # Now initialize for real
        print("Initializing extractor...")
        extractor = IosBackupExtractor(backup_directory=args.backup_dir, passphrase=backup_password)
        print(f"Backup is {'encrypted' if extractor.is_encrypted() else 'unencrypted'}.")

        # --- Perform Action ---
        if args.test:
            print("\n--- Testing Backup Access ---")
            success = extractor.test_backup_access()
            print(f"\nTest Result: {'SUCCESS' if success else 'FAILURE'}")
            exit(0 if success else 1)

        if args.save_manifest:
             print(f"\n--- Saving Manifest.db ---")
             extractor.save_manifest_file(args.save_manifest)

        if args.fileid or args.relpath or args.domain:
             print(f"\n--- Extracting Files ---")
             if args.fileid:
                 # Extract single file by ID
                 filename = args.fileid # Use fileID as filename if extracting single
                 output_file = os.path.join(args.output_dir, filename)
                 print(f"Extracting fileID {args.fileid} to {output_file}...")
                 extractor.extract_file(
                     file_id_sha1=args.fileid,
                     output_filename=output_file
                 )
                 print("Extraction complete.")
             else:
                 # Extract multiple files by path/domain patterns
                 print(f"Extracting files matching Path LIKE '{args.relpath or '%'}' and Domain LIKE '{args.domain or '%'}'...")
                 print(f"Output folder: {args.output_dir}")
                 print(f"Preserve Folders: {args.preserve_folders}")
                 print(f"Domain Subfolders: {args.domain_folders}")
                 print(f"Incremental: {args.incremental}")

                 extracted_count = extractor.extract_files(
                     output_folder=args.output_dir,
                     relative_paths_like=args.relpath,
                     domain_like=args.domain,
                     preserve_folders=args.preserve_folders,
                     domain_subfolders=args.domain_folders,
                     incremental=args.incremental
                 )
                 print(f"\nExtraction finished. Processed {extracted_count} file(s).")

    except (FileNotFoundError, ValueError, ImportError, ConnectionError, RuntimeError, sqlite3.Error) as e:
        print(f"\nERROR: {e}")
        # import traceback
        # traceback.print_exc() # Uncomment for detailed debug trace
        exit(1)
    except Exception as e:
        print(f"\nUNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
    finally:
         # Explicit cleanup call (though __del__ should handle it too)
         if extractor:
              extractor._cleanup()

    print("\nDone.")
    exit(0)
