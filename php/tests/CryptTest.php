<?php

use XRsa\Crypt;
use PHPUnit\Framework\TestCase;

class CryptTest extends TestCase
{
    public function testEncryptDecrypt()
    {
        $crypt = new Crypt(123456);
        $data = "Hello, World";
        $encrypted = $crypt->encrypt($data);
        $decrypted = $crypt->decrypt($encrypted);

        $this->assertEquals($data, $decrypted);
    }
}
