<?php

include('../vendor/autoload.php');

$hash = \Krzysztofzylka\Hash\Hash::hash('hash');
$checkHash = \Krzysztofzylka\Hash\Hash::checkHash($hash, 'hash');
$checkHash2 = \Krzysztofzylka\Hash\Hash::checkHash($hash, 'test');

var_dump(
    $hash, //$003$e661174850a6c7fcf99a
    $checkHash, //true
    $checkHash2 //false
);