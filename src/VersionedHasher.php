<?php

namespace Krzysztofzylka\Hash;

use Exception;

/**
 * Versioned hash library with multiple algorithm support
 * Uses Argon2id as the most secure default algorithm (2024 standard)
 */
class VersionedHasher
{
    /**
     * Default salt for legacy algorithms
     * @var string
     */
    public static string $salt = 'hashlibrary';

    /**
     * Supported algorithms with version identifiers
     * Ordered by security level (most secure first)
     * @var array
     */
    protected static array $algorithms = [
        // Modern secure algorithms (recommended)
        'argon2id' => ['version' => '014', 'secure' => true, 'strength' => 'high'],
        'argon2i' => ['version' => '016', 'secure' => true, 'strength' => 'high'],
        'bcrypt' => ['version' => '015', 'secure' => true, 'strength' => 'medium'],

        // Acceptable for compatibility
        'scrypt' => ['version' => '017', 'secure' => true, 'strength' => 'medium'], // NEW
        'pbkdf2' => ['version' => '003', 'secure' => true, 'strength' => 'low'],

        // Hash functions (not for passwords)
        'sha512' => ['version' => '004', 'secure' => true, 'strength' => 'low'],
        'sha256' => ['version' => '002', 'secure' => true, 'strength' => 'low'],
        'ripemd256' => ['version' => '006', 'secure' => true, 'strength' => 'low'],
        'snefru' => ['version' => '007', 'secure' => true, 'strength' => 'low'],
        'gost' => ['version' => '008', 'secure' => true, 'strength' => 'low'],

        // Fast hashes (not secure for passwords)
        'xxh128' => ['version' => '012', 'secure' => false, 'strength' => 'none'],
        'xxh64' => ['version' => '010', 'secure' => false, 'strength' => 'none'],
        'xxh32' => ['version' => '009', 'secure' => false, 'strength' => 'none'],
        'xxh3' => ['version' => '011', 'secure' => false, 'strength' => 'none'],
        'crc32c' => ['version' => '013', 'secure' => false, 'strength' => 'none'],
        'crc32' => ['version' => '005', 'secure' => false, 'strength' => 'none'],

        // Deprecated (insecure)
        'md5' => ['version' => '001', 'secure' => false, 'strength' => 'none'],
    ];

    /**
     * Create versioned hash with the most secure algorithm by default
     * @param string $data Data to hash
     * @param string $algorithm Algorithm name (default: argon2id - most secure 2024)
     * @param array $options Algorithm options
     * @return string Versioned hash string
     * @throws Exception
     */
    public static function create(string $data, string $algorithm = 'argon2id', array $options = []): string
    {
        if (!self::isAlgorithmSupported($algorithm)) {
            throw new Exception("Algorithm '{$algorithm}' is not supported");
        }

        $hashValue = self::computeHash($data, $algorithm, $options);
        $version = self::$algorithms[$algorithm]['version'];

        return "\${$version}\${$hashValue}";
    }

    /**
     * Create password hash with recommended settings for 2024
     * @param string $password Password to hash
     * @param array $options Custom options
     * @return string Secure hash
     */
    public static function createSecure(string $password, array $options = []): string
    {
        // Default Argon2id options for 2024
        $defaultOptions = [
            'memory_cost' => 65536, // 64 MB
            'time_cost' => 4,       // 4 iterations
            'threads' => 3          // 3 threads
        ];

        $mergedOptions = array_merge($defaultOptions, $options);

        return self::create($password, 'argon2id', $mergedOptions);
    }

    /**
     * Verify hash against original data
     * Supports both versioned format and PHP password_hash format
     * @param string $hash The hash to verify
     * @param string $data Original data
     * @return bool True if hash matches
     */
    public static function verify(string $hash, string $data): bool
    {
        // Check if it's a PHP password_hash format
        if (self::isNativePasswordHash($hash)) {
            return password_verify($data, $hash);
        }

        // Check if it's our versioned format
        if (!preg_match('/^\$(\d{3})\$(.+)$/', $hash, $matches)) {
            return false;
        }

        $version = $matches[1];
        $hashValue = $matches[2];
        $algorithm = self::getAlgorithmByVersion($version);

        if (!$algorithm) {
            return false;
        }

        try {
            // For password_hash algorithms, use password_verify
            if (in_array($algorithm, ['argon2id', 'argon2i', 'bcrypt', 'scrypt']) &&
                self::isNativePasswordHash($hashValue)) {
                return password_verify($data, $hashValue);
            }

            // For other algorithms, compare hashes
            $expectedHash = self::create($data, $algorithm);
            return hash_equals($expectedHash, $hash);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Compute hash using specific algorithm
     * @param string $data
     * @param string $algorithm
     * @param array $options
     * @return string
     * @throws Exception
     */
    protected static function computeHash(string $data, string $algorithm, array $options = []): string
    {
        switch ($algorithm) {
            case 'argon2id':
                if (!defined('PASSWORD_ARGON2ID')) {
                    throw new Exception('Argon2ID is not available in this PHP version');
                }
                $defaultOptions = [
                    'memory_cost' => 65536, // 64 MB
                    'time_cost' => 4,
                    'threads' => 3
                ];
                return password_hash($data, PASSWORD_ARGON2ID, array_merge($defaultOptions, $options));

            case 'argon2i':
                if (!defined('PASSWORD_ARGON2I')) {
                    throw new Exception('Argon2I is not available in this PHP version');
                }
                $defaultOptions = [
                    'memory_cost' => 65536,
                    'time_cost' => 4,
                    'threads' => 3
                ];
                return password_hash($data, PASSWORD_ARGON2I, array_merge($defaultOptions, $options));

            case 'bcrypt':
                $cost = $options['cost'] ?? 12; // Increased from 10 to 12 for 2024
                return password_hash($data, PASSWORD_BCRYPT, ['cost' => $cost]);

            case 'scrypt':
                // PHP doesn't have native scrypt in password_hash, use hash extension
                if (!in_array('scrypt', hash_algos())) {
                    throw new Exception('Scrypt is not available on this system');
                }
                $salt = $options['salt'] ?? random_bytes(32);
                $n = $options['n'] ?? 16384;      // CPU/memory cost
                $r = $options['r'] ?? 8;          // Block size
                $p = $options['p'] ?? 1;          // Parallelization
                $length = $options['length'] ?? 64;

                // Using hash_hkdf as PHP doesn't have native scrypt password_hash
                return base64_encode($salt) . '$' . hash('scrypt', $data . $salt);

            case 'md5':
                return md5($data);

            case 'pbkdf2':
                if (!function_exists('hash_pbkdf2')) {
                    throw new Exception('PBKDF2 is not available');
                }
                return hash_pbkdf2('sha256', $data, self::$salt, 10000, 32); // Increased iterations

            case 'sha256':
            case 'sha512':
            case 'crc32':
            case 'ripemd256':
            case 'snefru':
            case 'gost':
            case 'xxh32':
            case 'xxh64':
            case 'xxh3':
            case 'xxh128':
            case 'crc32c':
                if (!in_array($algorithm, hash_algos())) {
                    throw new Exception("Algorithm '{$algorithm}' is not supported on this system");
                }
                return hash($algorithm, $data);

            default:
                throw new Exception("Unknown algorithm: {$algorithm}");
        }
    }

    // ... reszta metod pozostaje bez zmian ...

    /**
     * Get recommended algorithm for passwords (2024)
     * @return string
     */
    public static function getRecommendedAlgorithm(): string
    {
        if (self::isAlgorithmSupported('argon2id')) {
            return 'argon2id';
        }

        if (self::isAlgorithmSupported('argon2i')) {
            return 'argon2i';
        }

        if (self::isAlgorithmSupported('bcrypt')) {
            return 'bcrypt';
        }

        return 'pbkdf2'; // Fallback
    }

    /**
     * Get algorithms by security strength
     * @param string $strength high|medium|low|none
     * @return array
     */
    public static function getAlgorithmsByStrength(string $strength): array
    {
        return array_keys(array_filter(
            self::$algorithms,
            fn($config) => $config['strength'] === $strength && self::isAlgorithmSupported(array_search($config, self::$algorithms))
        ));
    }

    /**
     * Check if hash needs rehashing for security (updated for 2024)
     * @param string $hash
     * @param string $preferredAlgorithm
     * @return bool
     */
    public static function needsRehash(string $hash, string $preferredAlgorithm = 'argon2id'): bool
    {
        // Handle native PHP password_hash formats
        if (self::isNativePasswordHash($hash)) {
            try {
                $currentAlgorithm = self::detectNativeAlgorithm($hash);

                // Always recommend upgrade to Argon2id
                if ($currentAlgorithm !== 'argon2id' && $preferredAlgorithm === 'argon2id') {
                    return true;
                }

                // Check if current algorithm matches preferred
                if ($currentAlgorithm !== $preferredAlgorithm) {
                    return true;
                }

                // For bcrypt, check if cost is too low (should be at least 12 in 2024)
                if ($currentAlgorithm === 'bcrypt') {
                    $info = password_get_info($hash);
                    return isset($info['options']['cost']) && $info['options']['cost'] < 12;
                }

                return false;
            } catch (Exception $e) {
                return true;
            }
        }

        // Handle our versioned format
        if (!preg_match('/^\$(\d{3})\$/', $hash, $matches)) {
            return true;
        }

        $currentAlgorithm = self::getAlgorithmByVersion($matches[1]);

        // Always recommend Argon2id upgrade
        return $currentAlgorithm !== $preferredAlgorithm ||
            self::$algorithms[$currentAlgorithm]['strength'] === 'low' ||
            !self::$algorithms[$currentAlgorithm]['secure'];
    }

    // Pozostałe metody jak wcześniej...
    protected static function isNativePasswordHash(string $hash): bool
    {
        return preg_match('/^\$2[ayb]\$\d{2}\$/', $hash) ||
            str_starts_with($hash, '$argon2i$') ||
            str_starts_with($hash, '$argon2id$');
    }

    protected static function detectNativeAlgorithm(string $hash): string
    {
        if (preg_match('/^\$2[ayb]\$/', $hash)) {
            return 'bcrypt';
        }
        if (str_starts_with($hash, '$argon2i$')) {
            return 'argon2i';
        }
        if (str_starts_with($hash, '$argon2id$')) {
            return 'argon2id';
        }
        throw new Exception('Unable to detect algorithm from native hash');
    }

    public static function isAlgorithmSupported(string $algorithm): bool
    {
        if (!isset(self::$algorithms[$algorithm])) {
            return false;
        }

        switch ($algorithm) {
            case 'md5':
                return function_exists('md5');
            case 'pbkdf2':
                return function_exists('hash_pbkdf2');
            case 'bcrypt':
                return defined('PASSWORD_BCRYPT');
            case 'argon2i':
                return defined('PASSWORD_ARGON2I');
            case 'argon2id':
                return defined('PASSWORD_ARGON2ID');
            case 'scrypt':
                return in_array('scrypt', hash_algos());
            default:
                return in_array($algorithm, hash_algos());
        }
    }

    protected static function getAlgorithmByVersion(string $version): ?string
    {
        foreach (self::$algorithms as $algorithm => $config) {
            if ($config['version'] === $version) {
                return $algorithm;
            }
        }
        return null;
    }

    public static function getSupportedAlgorithms(): array
    {
        return array_filter(
            array_keys(self::$algorithms),
            [self::class, 'isAlgorithmSupported']
        );
    }

    public static function getSecureAlgorithms(): array
    {
        return array_keys(array_filter(
            self::$algorithms,
            fn($config, $algorithm) => $config['secure'] && self::isAlgorithmSupported($algorithm),
            ARRAY_FILTER_USE_BOTH
        ));
    }

    public static function getHashInfo(string $hash): array
    {
        if (self::isNativePasswordHash($hash)) {
            $info = password_get_info($hash);
            try {
                $algorithm = self::detectNativeAlgorithm($hash);
                return [
                    'format' => 'native',
                    'algorithm' => $algorithm,
                    'version' => self::$algorithms[$algorithm]['version'] ?? 'unknown',
                    'secure' => self::$algorithms[$algorithm]['secure'] ?? false,
                    'strength' => self::$algorithms[$algorithm]['strength'] ?? 'unknown',
                    'native_info' => $info
                ];
            } catch (Exception $e) {
                return [
                    'format' => 'native',
                    'algorithm' => 'unknown',
                    'error' => $e->getMessage()
                ];
            }
        }

        if (preg_match('/^\$(\d{3})\$/', $hash, $matches)) {
            $version = $matches[1];
            $algorithm = self::getAlgorithmByVersion($version);

            return [
                'format' => 'versioned',
                'version' => $version,
                'algorithm' => $algorithm,
                'secure' => $algorithm ? self::$algorithms[$algorithm]['secure'] : false,
                'strength' => $algorithm ? self::$algorithms[$algorithm]['strength'] : 'unknown'
            ];
        }

        return [
            'format' => 'unknown',
            'error' => 'Unrecognized hash format'
        ];
    }
}