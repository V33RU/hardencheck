# ============================================================================
# Cryptographic Binary Detection Patterns
# ============================================================================
CRYPTO_BINARY_PATTERNS = {
    # Encryption/Decryption utilities
    "encrypt": ("encrypt", "MEDIUM", "Encryption utility - verify key management and algorithm strength"),
    "decrypt": ("decrypt", "HIGH", "Decryption utility - CRITICAL: verify key storage and access controls"),
    "crypt": ("encrypt", "MEDIUM", "Cryptographic utility - verify algorithm and key handling"),

    # Key generation and management
    "keygen": ("keygen", "MEDIUM", "Key generation utility - verify entropy source"),
    "genkey": ("keygen", "MEDIUM", "Key generation utility - verify randomness"),
    "keytool": ("keygen", "MEDIUM", "Key management utility - verify key storage"),
    "openssl": ("keygen", "MEDIUM", "OpenSSL utility - verify configuration"),

    # Hashing utilities
    "hash": ("hash", "LOW", "Hashing utility - verify algorithm strength"),
    "md5sum": ("hash", "MEDIUM", "MD5 hashing (weak) - consider SHA-256+"),
    "sha1sum": ("hash", "MEDIUM", "SHA-1 hashing (deprecated) - consider SHA-256+"),
    "sha256sum": ("hash", "LOW", "SHA-256 hashing utility"),
    "sha512sum": ("hash", "LOW", "SHA-512 hashing utility"),

    # Signing/Verification
    "sign": ("sign", "MEDIUM", "Digital signing utility - verify key protection"),
    "verify": ("verify", "LOW", "Signature verification utility"),
    "gpg": ("sign", "MEDIUM", "GPG encryption/signing - verify keyring security"),
    "gpg2": ("sign", "MEDIUM", "GPG2 encryption/signing - verify keyring security"),

    # Password/Key derivation
    "pbkdf2": ("keygen", "MEDIUM", "PBKDF2 key derivation - verify iteration count"),
    "scrypt": ("keygen", "MEDIUM", "Scrypt key derivation utility"),
    "bcrypt": ("keygen", "MEDIUM", "Bcrypt password hashing utility"),

    # Certificate utilities
    "certtool": ("keygen", "MEDIUM", "Certificate tool - verify key generation"),
    "certutil": ("keygen", "MEDIUM", "Certificate utility - verify key storage"),
}
