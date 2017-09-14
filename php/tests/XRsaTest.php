<?php

use XRsa\XRsa;
use XRsa\Pem;
use PHPUnit\Framework\TestCase;

class XRsaTest extends TestCase
{
    public function test_create_keys()
    {
        $keys = XRsa::createKeys(2048);
        $this->assertNotNull($keys['publicKey']);
        $this->assertNotNull($keys['privateKey']);

        return $keys;
    }

    /**
     * @depends test_create_keys
     * @param $keys
     */
    public function test_encrypt_decrypt($keys)
    {
        $rsa = new XRsa($keys['publicKey'], $keys['privateKey']);
        $data = "Hello, World";
        $encrypted = $rsa->publicEncrypt($data);
        $decrypted = $rsa->privateDecrypt($encrypted);

        $this->assertEquals($data, $decrypted);
    }

    /**
     * @depends test_create_keys
     * @param $keys
     */
    public function test_sign($keys)
    {
        $rsa = new XRsa($keys['publicKey'], $keys['privateKey']);
        $data = "Hello, World";
        $sign = $rsa->privateSign($data);
        $is_valid = $rsa->verifySign($data, $sign);

        $this->assertTrue($is_valid);
    }

    public function test_cross_language()
    {
        $testData = json_decode(file_get_contents(__DIR__. "/../../test/java.json"), true);
        $publicKey = Pem::base64ToPem(url_safe_base64_to_base64($testData['publicKey']), true);
        $privateKey = Pem::base64ToPem(url_safe_base64_to_base64($testData['privateKey']), false);
        $data = $testData['data'];
        $encrypted = $testData['encrypted'];
        $sign = $testData['sign'];

        $rsa = new XRsa($publicKey, $privateKey);
        $decrypted = $rsa->privateDecrypt($encrypted);
        $verify = $rsa->verifySign($data, $sign);

        $this->assertEquals($data, $decrypted);
        $this->assertEquals(1, $verify);
    }

}
