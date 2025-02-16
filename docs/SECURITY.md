# Security Documentation

## Cryptographic Design

### Key Derivation
- Argon2id with following parameters:
  - Memory: 65536 KB
  - Iterations: 4
  - Parallelism: 4
  - Salt: 16 random bytes
  - Output length: 32 bytes

### Encryption
- Algorithm: AES-256-GCM
- Key: 256-bit derived from password
- Nonce: 12 random bytes per encryption
- Associated Data: None (MAC covers ciphertext only)

### Digital Signatures
- Algorithm: Ed25519
- New keypair generated per session
- Signatures prevent tampering with encrypted data

## Security Considerations

### Password Handling
- Passwords never stored
- Secure key derivation prevents brute-force
- No password strength requirements enforced

### File Storage
- Only encrypted data stored on disk
- Original filenames not encrypted
- Metadata stored in clear (file sizes, timestamps)

### Error Handling
- Generic error messages to prevent information leakage
- Failed decryption attempts logged
- Rate limiting not implemented

## Security Recommendations

### Deployment
1. Use HTTPS for web API
2. Implement rate limiting
3. Add file integrity verification
4. Monitor failed decryption attempts
5. Regular security audits
6. Keep dependencies updated

### Usage
1. Use strong passwords
2. Secure password storage
3. Regular key rotation
4. Backup encrypted files
5. Monitor access logs