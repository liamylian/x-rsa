<?php

use XRsa\XRsa;
use PHPUnit\Framework\TestCase;

class XRsaTest extends TestCase
{
    private $public_key;

    private $private_key;

    public function setUp()
    {
        list($this->public_key, $this->private_key) = XRsa::createKeys(2048);
    }

    public function test_encrypt_decrypt()
    {
        $rsa = new XRsa($this->public_key, $this->private_key);
        $data = "Hello, World";
        $encrypted = $rsa->publicEncrypt($data);
        $decrypted = $rsa->privateDecrypt($encrypted);

        $this->assertEquals($data, $decrypted);
    }

    public function test_sign()
    {
        $rsa = new XRsa($this->public_key, $this->private_key);
        $data = "Hello, World";
        $sign = $rsa->privateSign($data);
        $is_valid = $rsa->verifySign($data, $sign);

        $this->assertTrue($is_valid);
    }
}
