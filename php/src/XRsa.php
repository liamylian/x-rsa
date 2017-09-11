<?php

namespace XRsa;

/**
 * @author williamylian
 *
 * Class UrlSafeRsa
 */
class XRsa
{
    protected $public_key;

    protected $private_key;

    protected $key_len;

    public function __construct($pub_key, $pri_key = null, $key_len = 2048)
    {
        $this->public_key = $pub_key;
        $this->private_key = $pri_key;
        $this->key_len = $key_len;
    }

    public static function createKeys($key_size = 2048)
    {
        $config = array(
            "private_key_bits" => $key_size,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $private_key);
        $public_key_detail = openssl_pkey_get_details($res);
        $public_key = $public_key_detail["key"];

        return [
            "public_key" => $public_key,
            "private_key" => $private_key,
        ];
    }

    public function publicEncrypt($data)
    {
        $encrypted = '';
        $part_len = $this->key_len / 8 - 11;
        $parts = str_split($data, $part_len);

        foreach ($parts as $part) {
            $encrypted_temp = '';
            openssl_public_encrypt($part, $encrypted_temp, $this->public_key);//公钥加密
            $encrypted .= $encrypted_temp;
        }

        return url_safe_base64_encode($encrypted);
    }

    public function privateDecrypt($encrypted)
    {
        $decrypted = "";
        $part_len = $this->key_len / 8;
        $base64_decoded = url_safe_base64_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);

        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_private_decrypt($part, $decrypted_temp,$this->private_key);//私钥解密
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

    public function privateSign($data)
    {
        openssl_sign($data, $sign, $this->private_key, OPENSSL_ALGO_SHA256);

        return url_safe_base64_encode($sign);
    }

    public function verifySign($data, $sign)
    {
        $pub_id = openssl_get_publickey($this->public_key);
        $res = openssl_verify($data, url_safe_base64_decode($sign), $pub_id, OPENSSL_ALGO_SHA256);

        return $res;
    }
}
