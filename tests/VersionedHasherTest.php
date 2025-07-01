<?php

use PHPUnit\Framework\TestCase;
use Krzysztofzylka\Hash\VersionedHasher;

class VersionedHasherTest extends TestCase
{
    protected function setUp(): void
    {
        // Reset salt to default before each test
        VersionedHasher::$salt = 'hashlibrary';
    }

    /**
     * Test basic hash creation with default algorithm
     */
    public function testCreateHashWithDefaultAlgorithm(): void
    {
        $data = 'test-password';
        $hash = VersionedHasher::create($data);

        $this->assertIsString($hash);
        $this->assertMatchesRegularExpression('/^\$\d{3}\$.+$/', $hash);
        $this->assertStringStartsWith('$003$', $hash); // pbkdf2 is default
    }

    /**
     * Test hash creation with specific algorithms
     */
    public function testCreateHashWithSpecificAlgorithms(): void
    {
        $data = 'test-data';

        // Test MD5
        if (VersionedHasher::isAlgorithmSupported('md5')) {
            $md5Hash = VersionedHasher::create($data, 'md5');
            $this->assertStringStartsWith('$001$', $md5Hash);
        }

        // Test SHA256
        if (VersionedHasher::isAlgorithmSupported('sha256')) {
            $sha256Hash = VersionedHasher::create($data, 'sha256');
            $this->assertStringStartsWith('$002$', $sha256Hash);
        }

        // Test PBKDF2
        if (VersionedHasher::isAlgorithmSupported('pbkdf2')) {
            $pbkdf2Hash = VersionedHasher::create($data, 'pbkdf2');
            $this->assertStringStartsWith('$003$', $pbkdf2Hash);
        }
    }

    /**
     * Test hash verification
     */
    public function testVerifyHash(): void
    {
        $data = 'my-secret-password';
        $hash = VersionedHasher::create($data, 'pbkdf2');

        $this->assertTrue(VersionedHasher::verify($hash, $data));
        $this->assertFalse(VersionedHasher::verify($hash, 'wrong-password'));
        $this->assertFalse(VersionedHasher::verify($hash, ''));
    }

    /**
     * Test hash verification with different algorithms
     */
    public function testVerifyHashWithDifferentAlgorithms(): void
    {
        $data = 'test-data-123';

        $supportedAlgorithms = ['md5', 'sha256', 'pbkdf2', 'sha512'];

        foreach ($supportedAlgorithms as $algorithm) {
            if (VersionedHasher::isAlgorithmSupported($algorithm)) {
                $hash = VersionedHasher::create($data, $algorithm);

                $this->assertTrue(
                    VersionedHasher::verify($hash, $data),
                    "Verification failed for algorithm: {$algorithm}"
                );

                $this->assertFalse(
                    VersionedHasher::verify($hash, 'wrong-data'),
                    "Verification should fail for wrong data with algorithm: {$algorithm}"
                );
            }
        }
    }

    /**
     * Test unsupported algorithm exception
     */
    public function testUnsupportedAlgorithmThrowsException(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage("Algorithm 'unsupported-algo' is not supported");

        VersionedHasher::create('test-data', 'unsupported-algo');
    }

    /**
     * Test invalid hash format returns false
     */
    public function testInvalidHashFormatReturnsFalse(): void
    {
        $invalidHashes = [
            'invalid-hash',
            '$abc$hash',
            '$12$hash',
            '$1234$hash',
            'no-dollar-signs',
            '$003',
            '$003$',
            ''
        ];

        foreach ($invalidHashes as $invalidHash) {
            $this->assertFalse(
                VersionedHasher::verify($invalidHash, 'test-data'),
                "Invalid hash format should return false: {$invalidHash}"
            );
        }
    }

    /**
     * Test algorithm support detection
     */
    public function testIsAlgorithmSupported(): void
    {
        // These should always be supported
        $this->assertTrue(VersionedHasher::isAlgorithmSupported('md5'));
        $this->assertTrue(VersionedHasher::isAlgorithmSupported('pbkdf2'));

        // This should not be supported
        $this->assertFalse(VersionedHasher::isAlgorithmSupported('non-existent'));
        $this->assertFalse(VersionedHasher::isAlgorithmSupported(''));
    }

    /**
     * Test getting supported algorithms
     */
    public function testGetSupportedAlgorithms(): void
    {
        $algorithms = VersionedHasher::getSupportedAlgorithms();

        $this->assertIsArray($algorithms);
        $this->assertNotEmpty($algorithms);
        $this->assertContains('md5', $algorithms);
        $this->assertContains('pbkdf2', $algorithms);
    }

    /**
     * Test getting secure algorithms only
     */
    public function testGetSecureAlgorithms(): void
    {
        $secureAlgorithms = VersionedHasher::getSecureAlgorithms();

        $this->assertIsArray($secureAlgorithms);
        $this->assertNotContains('md5', $secureAlgorithms); // MD5 is not secure
        $this->assertNotContains('crc32', $secureAlgorithms); // CRC32 is not secure
    }

    /**
     * Test needs rehash functionality
     */
    public function testNeedsRehash(): void
    {
        // Create hash with MD5 (insecure)
        if (VersionedHasher::isAlgorithmSupported('md5')) {
            $md5Hash = VersionedHasher::create('test-data', 'md5');
            $this->assertTrue(VersionedHasher::needsRehash($md5Hash, 'pbkdf2'));
        }

        // Create hash with PBKDF2 (secure)
        if (VersionedHasher::isAlgorithmSupported('pbkdf2')) {
            $pbkdf2Hash = VersionedHasher::create('test-data', 'pbkdf2');
            $this->assertFalse(VersionedHasher::needsRehash($pbkdf2Hash, 'pbkdf2'));
        }

        // Invalid hash format should need rehash
        $this->assertTrue(VersionedHasher::needsRehash('invalid-hash', 'pbkdf2'));
    }

    /**
     * Test custom salt functionality
     */
    public function testCustomSalt(): void
    {
        if (!VersionedHasher::isAlgorithmSupported('pbkdf2')) {
            $this->markTestSkipped('PBKDF2 not supported');
        }

        $data = 'test-password';

        // Create hash with default salt
        $hash1 = VersionedHasher::create($data, 'pbkdf2');

        // Change salt
        VersionedHasher::$salt = 'custom-salt-123';
        $hash2 = VersionedHasher::create($data, 'pbkdf2');

        // Hashes should be different due to different salts
        $this->assertNotEquals($hash1, $hash2);

        // Verification should work with current salt
        $this->assertTrue(VersionedHasher::verify($hash2, $data));

        // Reset salt back to default
        VersionedHasher::$salt = 'hashlibrary';

        // Old hash should still work with original salt context
        $this->assertFalse(VersionedHasher::verify($hash2, $data));
    }

    /**
     * Test hash consistency
     */
    public function testHashConsistency(): void
    {
        $data = 'consistency-test';

        foreach (['md5', 'sha256', 'pbkdf2'] as $algorithm) {
            if (VersionedHasher::isAlgorithmSupported($algorithm)) {
                $hash1 = VersionedHasher::create($data, $algorithm);
                $hash2 = VersionedHasher::create($data, $algorithm);

                if ($algorithm === 'argon2id') {
                    // Argon2ID generates different hashes each time (includes random salt)
                    $this->assertNotEquals($hash1, $hash2);
                    $this->assertTrue(VersionedHasher::verify($hash1, $data));
                    $this->assertTrue(VersionedHasher::verify($hash2, $data));
                } else {
                    // Other algorithms should be consistent
                    $this->assertEquals($hash1, $hash2, "Hash inconsistency for algorithm: {$algorithm}");
                }
            }
        }
    }

    /**
     * Test empty and special characters
     */
    public function testSpecialCharacters(): void
    {
        $specialData = [
            '',
            ' ',
            'ąćęłńóśźż',
            '🚀🎉',
            "line1\nline2",
            'tab\there',
            'quote"test\'quote',
            'null\0byte'
        ];

        foreach ($specialData as $data) {
            $hash = VersionedHasher::create($data, 'pbkdf2');
            $this->assertTrue(
                VersionedHasher::verify($hash, $data),
                "Failed to verify special character data: " . json_encode($data)
            );
        }
    }

    /**
     * Test version extraction from hash
     */
    public function testVersionExtraction(): void
    {
        $data = 'version-test';

        // Test different algorithms and their versions
        $expectedVersions = [
            'md5' => '001',
            'sha256' => '002',
            'pbkdf2' => '003',
            'sha512' => '004'
        ];

        foreach ($expectedVersions as $algorithm => $expectedVersion) {
            if (VersionedHasher::isAlgorithmSupported($algorithm)) {
                $hash = VersionedHasher::create($data, $algorithm);

                preg_match('/^\$(\d{3})\$/', $hash, $matches);
                $this->assertEquals(
                    $expectedVersion,
                    $matches[1],
                    "Version mismatch for algorithm: {$algorithm}"
                );
            }
        }
    }

    /**
     * Test performance with large data
     */
    public function testLargeDataPerformance(): void
    {
        $largeData = str_repeat('Large data test ', 1000); // ~15KB

        $startTime = microtime(true);
        $hash = VersionedHasher::create($largeData, 'sha256');
        $endTime = microtime(true);

        $this->assertLessThan(1.0, $endTime - $startTime, 'Hash creation took too long');
        $this->assertTrue(VersionedHasher::verify($hash, $largeData));
    }

    /**
     * Test thread safety simulation
     */
    public function testConcurrentHashCreation(): void
    {
        $data = 'concurrent-test';
        $hashes = [];

        // Simulate concurrent hash creation
        for ($i = 0; $i < 10; $i++) {
            $hashes[] = VersionedHasher::create($data, 'pbkdf2');
        }

        // All hashes should be identical (for deterministic algorithms)
        $firstHash = $hashes[0];
        foreach ($hashes as $hash) {
            $this->assertEquals($firstHash, $hash);
            $this->assertTrue(VersionedHasher::verify($hash, $data));
        }
    }

    public function testPasswordHash(): void
    {
        $password = 'testpassword';
        $hashed = password_hash($password, PASSWORD_DEFAULT);
        $this->assertTrue(password_verify($password, $hashed));
        $this->assertFalse(password_verify('wrongpassword', $hashed));
        $this->assertFalse(password_verify('', $hashed));
    }
}