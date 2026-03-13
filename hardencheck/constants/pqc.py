# ============================================================================
# Post-Quantum Cryptography (PQC) Readiness Detection Patterns
# ============================================================================
# NIST PQC Standards (2024): ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+)

# Quantum-vulnerable algorithms: (patterns, severity, description)
QUANTUM_VULNERABLE_ALGOS = {
    "RSA": {
        "patterns": [
            "RSA_sign", "RSA_verify", "RSA_encrypt", "RSA_decrypt",
            "RSA_public_encrypt", "RSA_private_decrypt", "rsa_pkcs1",
            "RSA_generate_key", "RSA_new", "RSA_size",
            "EVP_PKEY_RSA", "rsa_oaep", "rsa_pss",
        ],
        "severity": "HIGH",
        "description": "RSA is vulnerable to Shor's algorithm on quantum computers",
    },
    "ECDSA": {
        "patterns": [
            "ECDSA_sign", "ECDSA_verify", "ECDSA_do_sign",
            "EC_KEY_new", "EC_KEY_generate_key", "EC_GROUP_new",
            "secp256r1", "secp384r1", "secp521r1", "prime256v1",
            "EVP_PKEY_EC", "ecdsa_with",
        ],
        "severity": "HIGH",
        "description": "ECDSA is vulnerable to Shor's algorithm on quantum computers",
    },
    "DH": {
        "patterns": [
            "DH_compute_key", "DH_generate_key", "DH_generate_parameters",
            "DH_new", "DH_size", "EVP_PKEY_DH",
        ],
        "severity": "HIGH",
        "description": "Diffie-Hellman key exchange is quantum-vulnerable",
    },
    "ECDH": {
        "patterns": [
            "ECDH_compute_key", "EC_KEY_set_private_key",
            "X25519", "x25519", "curve25519",
        ],
        "severity": "HIGH",
        "description": "ECDH key agreement is vulnerable to quantum attacks",
    },
    "DSA": {
        "patterns": [
            "DSA_sign", "DSA_verify", "DSA_generate_key",
            "DSA_new", "EVP_PKEY_DSA", "dsa_with",
        ],
        "severity": "CRITICAL",
        "description": "DSA is deprecated (classically weak) and quantum-vulnerable",
    },
    "Ed25519": {
        "patterns": [
            "ED25519", "ed25519", "Ed25519",
            "EVP_PKEY_ED25519", "ed25519_sign", "ed25519_verify",
        ],
        "severity": "MEDIUM",
        "description": "Ed25519 is classically secure but quantum-vulnerable for signatures",
    },
    "DES": {
        "patterns": [
            "DES_ecb_encrypt", "DES_cbc_encrypt", "DES_ede3",
            "des_cbc", "des_ecb", "3des", "triple_des",
        ],
        "severity": "CRITICAL",
        "description": "DES/3DES is broken classically and quantum-vulnerable",
    },
    "MD5": {
        "patterns": [
            "MD5_Init", "MD5_Update", "MD5_Final",
            "EVP_md5", "md5_digest",
        ],
        "severity": "CRITICAL",
        "description": "MD5 is cryptographically broken for signing/integrity",
    },
    "SHA1": {
        "patterns": [
            "SHA1_Init", "SHA1_Update", "SHA1_Final",
            "EVP_sha1", "sha1_digest",
        ],
        "severity": "HIGH",
        "description": "SHA-1 is deprecated and collision-prone",
    },
}

# Post-Quantum Cryptography algorithm detection patterns
PQC_ALGORITHM_PATTERNS = {
    "ML-KEM (Kyber)": {
        "patterns": [
            "kyber", "Kyber", "KYBER", "ML-KEM", "mlkem", "MLKEM",
            "OQS_KEM_kyber", "kyber512", "kyber768", "kyber1024",
            "pqcrystals_kyber",
        ],
        "type": "KEM",
        "standard": "FIPS 203",
    },
    "ML-DSA (Dilithium)": {
        "patterns": [
            "dilithium", "Dilithium", "DILITHIUM", "ML-DSA", "mldsa", "MLDSA",
            "OQS_SIG_dilithium", "dilithium2", "dilithium3", "dilithium5",
            "pqcrystals_dilithium",
        ],
        "type": "Signature",
        "standard": "FIPS 204",
    },
    "SLH-DSA (SPHINCS+)": {
        "patterns": [
            "sphincs", "SPHINCS", "SLH-DSA", "slhdsa", "SLHDSA",
            "OQS_SIG_sphincs", "sphincsplus",
        ],
        "type": "Signature",
        "standard": "FIPS 205",
    },
    "XMSS": {
        "patterns": [
            "xmss", "XMSS", "xmssmt", "XMSSMT",
        ],
        "type": "Signature",
        "standard": "RFC 8391",
    },
    "FrodoKEM": {
        "patterns": [
            "frodo", "Frodo", "FrodoKEM", "frodokem",
            "OQS_KEM_frodo",
        ],
        "type": "KEM",
        "standard": "NIST Round 3 Alternate",
    },
    "BIKE": {
        "patterns": [
            "BIKE", "bike_", "OQS_KEM_bike",
        ],
        "type": "KEM",
        "standard": "NIST Round 4",
    },
    "HQC": {
        "patterns": [
            "HQC", "hqc_", "OQS_KEM_hqc",
        ],
        "type": "KEM",
        "standard": "NIST Round 4",
    },
}

# Hybrid mode patterns (classical + PQC combined)
PQC_HYBRID_PATTERNS = [
    "x25519_kyber", "p256_mlkem", "x25519_mlkem",
    "p384_mlkem", "SecP256r1MLKEM768", "X25519MLKEM768",
    "hybrid_kem", "hybrid_sig", "composite_sig",
    "OQS_KEM_HYBRID", "PQ_HYBRID",
]

# Crypto libraries and their PQC support status
PQC_READY_LIBRARIES = {
    "OpenSSL": {
        "patterns": ["OpenSSL", "openssl", "libssl", "libcrypto"],
        "version_patterns": [r"OpenSSL\s+(\d+\.\d+\.\d+)", r"libssl\.so\.(\d+\.\d+)"],
        "min_pqc_version": "3.5.0",
        "pqc_note": "PQC provider via oqsprovider or built-in (3.5+)",
    },
    "wolfSSL": {
        "patterns": ["wolfSSL", "wolfssl", "libwolfssl"],
        "version_patterns": [r"wolfSSL\s+(\d+\.\d+\.\d+)"],
        "min_pqc_version": "5.5.0",
        "pqc_note": "ML-KEM and ML-DSA support via liboqs integration",
    },
    "BoringSSL": {
        "patterns": ["BoringSSL", "boringssl", "libboringssl"],
        "version_patterns": [],
        "min_pqc_version": "0.0.0",
        "pqc_note": "ML-KEM-768 built-in for TLS 1.3",
    },
    "liboqs": {
        "patterns": ["liboqs", "oqs_", "OQS_"],
        "version_patterns": [r"liboqs\s+(\d+\.\d+\.\d+)"],
        "min_pqc_version": "0.0.0",
        "pqc_note": "Dedicated PQC library - all NIST algorithms supported",
    },
    "libsodium": {
        "patterns": ["libsodium", "sodium_", "crypto_box"],
        "version_patterns": [r"libsodium\s+(\d+\.\d+\.\d+)"],
        "min_pqc_version": "99.99.99",
        "pqc_note": "No PQC support yet - only classical crypto",
    },
    "GnuTLS": {
        "patterns": ["GnuTLS", "gnutls", "libgnutls"],
        "version_patterns": [r"GnuTLS\s+(\d+\.\d+\.\d+)"],
        "min_pqc_version": "3.8.8",
        "pqc_note": "Experimental PQC support (3.8.8+)",
    },
    "mbedTLS": {
        "patterns": ["mbedTLS", "mbedtls", "libmbedtls", "mbed TLS"],
        "version_patterns": [r"mbed\s*TLS\s+(\d+\.\d+\.\d+)"],
        "min_pqc_version": "4.0.0",
        "pqc_note": "PQC support planned for 4.0+",
    },
}

# PQC readiness classification
PQC_READINESS_LEVELS = {
    "READY": "Uses PQC algorithms - quantum-resistant",
    "HYBRID": "Classical + PQC combined - transition mode",
    "NOT_READY": "Only classical algorithms - quantum-vulnerable",
    "CRITICAL": "Uses deprecated/broken algorithms (DSA, DES, MD5)",
}
