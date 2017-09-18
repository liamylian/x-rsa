<?php

use XRsa\XRsa;
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
    public function test_public_encrypt_private_decrypt($keys)
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
    public function test_private_encrypt_public_decrypt($keys)
    {
        $rsa = new XRsa($keys['publicKey'], $keys['privateKey']);
        $data = "Hello, World";
        $encrypted = $rsa->privateEncrypt($data);
        $decrypted = $rsa->publicDecrypt($encrypted);

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
        $sign = $rsa->sign($data);
        $is_valid = $rsa->verify($data, $sign);

        $this->assertEquals(1, $is_valid);
    }

    public function test_cross_language()
    {
        $publicKey = file_get_contents(__DIR__. "/../../test/pub.pem");
        $privateKey = file_get_contents(__DIR__. "/../../test/pri.pem");
        $testData = json_decode(file_get_contents(__DIR__. "/../../test/data.json"), true);
        $data = $testData['data'];
        $encrypted = $testData['encrypted'];
        $sign = $testData['sign'];

        $rsa = new XRsa($publicKey, $privateKey);
        $decrypted = $rsa->privateDecrypt($encrypted);
        $verify = $rsa->verify($data, $sign);

        $this->assertEquals($data, $decrypted);
        $this->assertEquals(1, $verify);
    }

}
