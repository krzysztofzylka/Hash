<?php

namespace Krzysztofzylka\Hash\Tests;

use Krzysztofzylka\Hash\Hash;
use Exception;
use PHPUnit\Framework\TestCase;

/**
 * HashTest Class
 * 
 * This class is used to test the hash and checkHash functions of the Hash class
 * It checks for the different methods provided by the Hash class.
 */
class HashTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testMd5Hash(): void
    {
        $hash = Hash::hash("test", 'md5');
        $this->assertEquals('001', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(37, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testSha256Hash(): void
    {
        $hash = Hash::hash("test", 'sha256');
        $this->assertEquals('002', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(69, strlen($hash));
    }

   /**
    * @throws Exception
    */
    public function testPbkdf2Hash(): void
    {
        $hash = Hash::hash("test", 'pbkdf2');
        $this->assertEquals('003', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(25, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testSha512Hash(): void
    {
        $hash = Hash::hash("test", 'sha512');
        $this->assertEquals('004', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(133, strlen($hash));
    }


    /**
     * @throws Exception
     */
    public function testCr32Hash(): void
    {
        $hash = Hash::hash("test", 'crc32');
        $this->assertEquals('005', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(13, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testRipemd256Hash(): void
    {
        $hash = Hash::hash("test", 'ripemd256');
        $this->assertEquals('006', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(69, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testSnefruHash(): void
    {
        $hash = Hash::hash("test", 'snefru');
        $this->assertEquals('007', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(69, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testGostHash(): void
    {
        $hash = Hash::hash("test", 'gost');
        $this->assertEquals('008', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(69, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testXXH32Hash(): void
    {
        $hash = Hash::hash("test", 'xxh32');
        $this->assertEquals('009', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(13, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testXXH64Hash(): void
    {
        $hash = Hash::hash("test", 'xxh64');
        $this->assertEquals('010', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(21, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testXXH3Hash(): void
    {
        $hash = Hash::hash("test", 'xxh3');
        $this->assertEquals('011', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(21, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testXXH128Hash(): void
    {
        $hash = Hash::hash("test", 'xxh128');
        $this->assertEquals('012', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(37, strlen($hash));
    }

    /**
     * @throws Exception
     */
    public function testCrc32cHash(): void
    {
        $hash = Hash::hash("test", 'crc32c');
        $this->assertEquals('013', substr($hash, 1, 3));
        $this->assertTrue(Hash::checkHash($hash, "test"));
        $this->assertEquals(13, strlen($hash));
    }


}