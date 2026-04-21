<?php

namespace Krzysztofzylka\Hash;

use Exception;
use InvalidArgumentException;
use Random\RandomException;
use SodiumException;

class VersionedEncryption
{

    private const string PREFIX = 'enc';

    private const string VERSION = '001';

    private const string CIPHER = 'xchacha20poly1305';

    private const int NONCE_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    private const int KEY_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

    private const int TAG_LENGTH = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

    private string $masterKey;

    /**
     * @throws Exception
     */
    public function __construct(string $masterKey)
    {
        if (!self::isSupported()) {
            throw new Exception('Libsodium extension is not available');
        }

        if ($masterKey === '') {
            throw new InvalidArgumentException('Master key must not be empty');
        }

        $this->masterKey = $masterKey;
    }

    /**
     * Encrypts plaintext into a versioned payload.
     *
     * @throws Exception
     */
    public function encrypt(string $plainText, string $context = ''): string
    {
        $nonce = random_bytes(self::NONCE_LENGTH);
        $cipherText = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plainText,
            $context,
            $nonce,
            $this->deriveKey()
        );

        return self::PREFIX
            . '$v' . self::VERSION
            . '$' . self::CIPHER
            . '$' . base64_encode($nonce . $cipherText);
    }

    /**
     * Decrypts a versioned payload.
     *
     * @throws Exception
     */
    public function decrypt(string $payload, string $context = ''): string
    {
        $parsed = $this->parsePayload($payload);
        $decoded = base64_decode($parsed['encoded'], true);

        if ($decoded === false) {
            throw new Exception('Invalid encrypted payload encoding');
        }

        if (strlen($decoded) < self::NONCE_LENGTH + self::TAG_LENGTH) {
            throw new Exception('Encrypted payload is too short');
        }

        $nonce = substr($decoded, 0, self::NONCE_LENGTH);
        $cipherText = substr($decoded, self::NONCE_LENGTH);
        $plainText = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $cipherText,
            $context,
            $nonce,
            $this->deriveKey()
        );

        if ($plainText === false) {
            throw new Exception('Decryption failed - invalid key, context or corrupted data');
        }

        return $plainText;
    }

    public function needsReencrypt(string $payload): bool
    {
        if (!preg_match('/^' . self::PREFIX . '\$v(\d{3})\$([a-z0-9]+)\$(.+)$/', $payload, $matches)) {
            return true;
        }

        return $matches[1] !== self::VERSION || $matches[2] !== self::CIPHER;
    }

    public function getInfo(string $payload): array
    {
        if (!preg_match('/^' . self::PREFIX . '\$v(\d{3})\$([a-z0-9]+)\$(.+)$/', $payload, $matches)) {
            return [
                'format' => 'unknown',
                'error' => 'Unrecognized encrypted payload format',
            ];
        }

        return [
            'format' => self::PREFIX,
            'version' => $matches[1],
            'cipher' => $matches[2],
            'supported' => $matches[1] === self::VERSION && $matches[2] === self::CIPHER,
        ];
    }

    /**
     * @return string
     * @throws RandomException
     */
    public static function generateKey(): string
    {
        return base64_encode(random_bytes(self::KEY_LENGTH));
    }

    /**
     * @return bool
     */
    public static function isSupported(): bool
    {
        return function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt') &&
            function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt') &&
            function_exists('sodium_crypto_generichash');
    }

    /**
     * @return string
     * @throws SodiumException
     */
    private function deriveKey(): string
    {
        return sodium_crypto_generichash($this->masterKey, '', self::KEY_LENGTH);
    }

    /**
     * @return array{version: string, cipher: string, encoded: string}
     * @throws Exception
     */
    private function parsePayload(string $payload): array
    {
        if (!preg_match('/^' . self::PREFIX . '\$v(\d{3})\$([a-z0-9]+)\$(.+)$/', $payload, $matches)) {
            throw new Exception('Invalid encrypted payload format');
        }

        if ($matches[1] !== self::VERSION) {
            throw new Exception("Unsupported encrypted payload version '{$matches[1]}'");
        }

        if ($matches[2] !== self::CIPHER) {
            throw new Exception("Unsupported cipher '{$matches[2]}'");
        }

        return [
            'version' => $matches[1],
            'cipher' => $matches[2],
            'encoded' => $matches[3],
        ];
    }

}
