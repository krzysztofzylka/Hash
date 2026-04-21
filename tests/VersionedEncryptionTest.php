<?php

namespace Krzysztofzylka\tests;

use Krzysztofzylka\Hash\VersionedEncryption;
use PHPUnit\Framework\TestCase;

class VersionedEncryptionTest extends TestCase
{
    private string $masterKey;

    private VersionedEncryption $encryption;

    protected function setUp(): void
    {
        if (!VersionedEncryption::isSupported()) {
            $this->markTestSkipped('Libsodium is not available');
        }

        $this->masterKey = 'test-master-key-1234567890';
        $this->encryption = new VersionedEncryption($this->masterKey);
    }

    public function testConstructorRejectsEmptyKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Master key must not be empty');

        new VersionedEncryption('');
    }

    public function testEncryptReturnsVersionedPayload(): void
    {
        $payload = $this->encryption->encrypt('hello world');

        $this->assertMatchesRegularExpression('/^enc\$v001\$xchacha20poly1305\$[A-Za-z0-9+\/=]+$/', $payload);
        $this->assertStringNotContainsString('hello world', $payload);
    }

    public function testEncryptAndDecryptRoundTrip(): void
    {
        $payload = $this->encryption->encrypt('secret message');

        $this->assertSame('secret message', $this->encryption->decrypt($payload));
    }

    public function testEncryptAndDecryptEmptyString(): void
    {
        $payload = $this->encryption->encrypt('');

        $this->assertSame('', $this->encryption->decrypt($payload));
    }

    public function testDecryptFailsWithDifferentKey(): void
    {
        $payload = $this->encryption->encrypt('secret message');
        $otherEncryption = new VersionedEncryption('different-master-key-1234567890');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Decryption failed - invalid key, context or corrupted data');

        $otherEncryption->decrypt($payload);
    }

    public function testDecryptFailsWithDifferentContext(): void
    {
        $payload = $this->encryption->encrypt('secret message', 'account:1');

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Decryption failed - invalid key, context or corrupted data');

        $this->encryption->decrypt($payload, 'account:2');
    }

    public function testSpecialCharactersRoundTrip(): void
    {
        $plainText = "Zażółć gęślą jaźń 🚀\nline2\tquoted\"'";
        $payload = $this->encryption->encrypt($plainText, 'special');

        $this->assertSame($plainText, $this->encryption->decrypt($payload, 'special'));
    }

    public function testNeedsReencrypt(): void
    {
        $payload = $this->encryption->encrypt('secret message');

        $this->assertFalse($this->encryption->needsReencrypt($payload));
        $this->assertTrue($this->encryption->needsReencrypt('invalid-payload'));
    }

    public function testGetInfoReturnsPayloadMetadata(): void
    {
        $payload = $this->encryption->encrypt('secret message');
        $info = $this->encryption->getInfo($payload);

        $this->assertSame('enc', $info['format']);
        $this->assertSame('001', $info['version']);
        $this->assertSame('xchacha20poly1305', $info['cipher']);
        $this->assertTrue($info['supported']);
    }

    public function testGenerateKeyReturnsString(): void
    {
        $key = VersionedEncryption::generateKey();

        $this->assertNotEmpty($key);
        $this->assertIsString($key);
    }
}
