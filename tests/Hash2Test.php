<?php

use PHPUnit\Framework\TestCase;
use Krzysztofzylka\Hash\Hash;

/**
 * @desc This class performs tests on the `checkHash` method in the Hash class.
 * The `checkHash` method is supposed to verify whether a provided hash matches
 * the hashed representation of the given string, using the same encryption algorithm.
 */
class Hash2Test extends TestCase
{
    /**
     * @desc Test to ensure that the `checkHash` method works as expected.
     * The test involves creating a hash with the `hash` method and checking it using the `checkHash` method.
     * We expect the `checkHash` method to return true, certifying that the hash is valid.
     */
    public function testCheckHashMethodReturnsTrue()
    {
        $string     = "this is a test string";
        $algorithm  = "md5";
        $valid_hash = Hash::hash($string, $algorithm);

        $this->assertTrue(Hash::checkHash($valid_hash, $string));
    }

    /**
     * @desc Test to ensure that the `checkHash` method works as expected.
     * Here, we're testing a negative case where we provide an invalid hash.
     * We expect the `checkHash` method to return false, indicating the hash is invalid.
     */
    public function testCheckHashMethodReturnsFalseForInvalidHash()
    {
        $string          = "this is a test string";
        $invalid_hash = "invalid_hash";

        $this->assertFalse(Hash::checkHash($invalid_hash, $string));
    }
}