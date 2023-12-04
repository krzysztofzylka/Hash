<?php

namespace Krzysztofzylka\Hash;

use Exception;

class Hash
{

    /**
     * Hash salt
     * @var string
     */
    public static string $SALT = 'hashlibrary';

    /**
     * Hash list
     * @var array
     * @ignore
     */
    protected static array $HASH_LIST = [
        'md5' => ['number' => '001'],
        'sha256' => ['number' => '002'],
        'pbkdf2' => ['number' => '003'],
        'sha512' => ['number' => '004'],
        'crc32' => ['number' => '005'],
        'ripemd256' => ['number' => '006'],
        'snefru' => ['number' => '007'],
        'gost' => ['number' => '008'],
        'xxh32' => ['number' => '009'],
        'xxh64' => ['number' => '010'],
        'xxh3' => ['number' => '011'],
        'xxh128' => ['number' => '012'],
        'crc32c' => ['number' => '013']
    ];

    /**
     * Hash string
     * @param string $string
     * @param string $algorithm Algorithm, default pbkdf2 (md5, sha256, pbkdf2, sha512, crc32, ripemd256, snefri, gost)
     * @return string
     * @throws Exception
     */
    public static function hash(string $string, string $algorithm = 'pbkdf2'): string
    {
        $return = '${type}${hash}';
        $hash = '';

        switch ($algorithm) {
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
                $hash = hash($algorithm, $string);
                break;
            case 'md5':
                $hash = md5($string);
                break;
            case 'pbkdf2':
                if (!function_exists('hash_pbkdf2')) {
                    throw new Exception('Unknown function hash_pbkdf2');
                }

                $hash = hash_pbkdf2('sha256', $string, self::$SALT, 4096, 20);
                break;
        }

        return str_replace(
            [
                '{type}',
                '{hash}'
            ],
            [
                self::$HASH_LIST[$algorithm]['number'],
                $hash
            ],
            $return
        );
    }

    /**
     * Check hash
     * @param string $hash
     * @param string $string
     * @return bool
     * @throws Exception
     */
    public static function checkHash(string $hash, string $string): bool
    {
        $hashNumber = str_replace('$', '', substr($hash, 0, 4));
        $hashIndex = array_search($hashNumber, array_column(self::$HASH_LIST, 'number'));

        if (is_bool($hashIndex)) {
            return false;
        }

        $hashName = array_keys(self::$HASH_LIST)[$hashIndex];

        return $hash === self::hash($string, $hashName);
    }

}