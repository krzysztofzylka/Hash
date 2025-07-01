# VersionedHasher

A modern PHP library for secure password hashing and general-purpose hashing with version support and algorithm migration capabilities.

## Features

- **Modern Security**: Uses Argon2id as the default algorithm (2024 security standard)
- **Version Management**: Built-in versioning system for seamless algorithm migration
- **Multiple Algorithms**: Support for 15+ hashing algorithms from secure password hashers to fast checksums
- **Backward Compatibility**: Seamlessly works with existing PHP `password_hash()` outputs
- **Security Assessment**: Built-in tools to evaluate hash strength and recommend upgrades
- **Migration Ready**: Easy detection of hashes that need security upgrades

## Installation

```bash
composer require krzysztofzylka/hash
```

## Quick Start

### Secure Password Hashing

```php
use Krzysztofzylka\Hash\VersionedHasher;

// Create a secure password hash (uses Argon2id by default)
$hash = VersionedHasher::createSecure('mypassword');
// Output: $014$argon2id$v=19$m=65536,t=4,p=3$base64salt$base64hash

// Verify password
$isValid = VersionedHasher::verify($hash, 'mypassword'); // true
```

### Custom Algorithm Usage

```php
// Use specific algorithm
$hash = VersionedHasher::create('data', 'bcrypt', ['cost' => 12]);
$hash = VersionedHasher::create('data', 'sha256');
$hash = VersionedHasher::create('data', 'xxh64'); // Fast checksum

// Verify any supported hash
$isValid = VersionedHasher::verify($hash, 'data');
```

## Supported Algorithms

### Password Hashing (Secure)
- **argon2id** ⭐ (Recommended 2024) - Most secure, resistant to all attacks
- **argon2i** - Secure alternative to Argon2id
- **bcrypt** - Widely supported, good security
- **scrypt** - Memory-hard function
- **pbkdf2** - Minimum acceptable security

### Cryptographic Hashes
- **sha512** / **sha256** - Standard cryptographic hashes
- **ripemd256** - Alternative cryptographic hash
- **snefru** / **gost** - Specialized cryptographic functions

### Fast Checksums (Non-secure)
- **xxh128** / **xxh64** / **xxh32** / **xxh3** - Ultra-fast checksums
- **crc32** / **crc32c** - Standard checksums

### Legacy (Deprecated)
- **md5** - Only for compatibility (not secure)

## Advanced Usage

### Security Assessment

```php
// Check if hash needs upgrade
$needsUpgrade = VersionedHasher::needsRehash($oldHash);
if ($needsUpgrade) {
    $newHash = VersionedHasher::createSecure($password);
    // Update database with new hash
}

// Get hash information
$info = VersionedHasher::getHashInfo($hash);
/*
Array(
    'format' => 'versioned',
    'algorithm' => 'argon2id',
    'version' => '014',
    'secure' => true,
    'strength' => 'high'
)
*/
```

### Algorithm Discovery

```php
// Get recommended algorithm for current system
$recommended = VersionedHasher::getRecommendedAlgorithm(); // 'argon2id'

// Get all supported algorithms
$all = VersionedHasher::getSupportedAlgorithms();

// Get only secure algorithms
$secure = VersionedHasher::getSecureAlgorithms();

// Get algorithms by strength
$high = VersionedHasher::getAlgorithmsByStrength('high');
```

### Custom Configuration

```php
// Custom Argon2id settings
$hash = VersionedHasher::create('password', 'argon2id', [
    'memory_cost' => 131072, // 128 MB
    'time_cost' => 6,        // 6 iterations
    'threads' => 4           // 4 threads
]);

// Custom bcrypt cost
$hash = VersionedHasher::create('password', 'bcrypt', ['cost' => 14]);

// Custom PBKDF2 settings
$hash = VersionedHasher::create('password', 'pbkdf2', [
    'iterations' => 20000
]);
```

## Security Recommendations (2024)

### For New Applications
1. **Use `createSecure()`** - Automatically uses Argon2id with optimal settings
2. **Regular Assessment** - Check `needsRehash()` periodically
3. **Monitor Algorithms** - Stay updated on algorithm recommendations

### For Legacy Applications
1. **Gradual Migration** - Use `needsRehash()` to identify upgrade candidates
2. **Backward Compatibility** - Library works with existing `password_hash()` outputs
3. **User Login Migration** - Upgrade hashes during successful logins

```php
// Migration example
if (VersionedHasher::verify($storedHash, $inputPassword)) {
    // Login successful
    if (VersionedHasher::needsRehash($storedHash)) {
        $newHash = VersionedHasher::createSecure($inputPassword);
        // Update database with $newHash
    }
    // Continue with login process
}
```

## Version Format

The library uses a versioned format for all hashes:
```
$VERSION$HASH_VALUE
```

Examples:
- `$014$argon2id$v=19$m=65536,t=4,p=3$...` - Argon2id
- `$015$2y$12$abcdef...` - bcrypt
- `$002$a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3` - SHA256

## Performance Guidelines

### Password Hashing
- **High Security**: Argon2id with 128MB+ memory
- **Balanced**: Default `createSecure()` settings (64MB, 4 iterations)
- **Fast**: bcrypt with cost 12

### Checksums
- **Ultra Fast**: xxh64, xxh3
- **Standard**: crc32, crc32c
- **Cryptographic**: sha256, sha512

## Error Handling

```php
try {
    $hash = VersionedHasher::create('data', 'unsupported_algo');
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}

// Check algorithm support before use
if (VersionedHasher::isAlgorithmSupported('argon2id')) {
    $hash = VersionedHasher::create('data', 'argon2id');
}
```

## Requirements

- PHP 7.4+
- Hash extension (usually included)
- For Argon2: PHP 7.2+ with password_hash Argon2 support
- For scrypt: libsodium or hash extension with scrypt support

## Security Notes

⚠️ **Important Security Considerations:**

1. **Never use fast checksums for passwords** (xxh*, crc32, md5)
2. **Upgrade legacy hashes** regularly using `needsRehash()`
3. **Use secure algorithms** for sensitive data
4. **Monitor algorithm recommendations** as security standards evolve
5. **Test algorithm availability** in your environment

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

## Support

For issues and questions:
- GitHub Issues: [repository-url]
- Documentation: [docs-url]