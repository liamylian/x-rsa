<?php

namespace XRsa;

class XRsa
{
    const RSA_ALGORITHM_SIGN = OPENSSL_ALGO_SHA256;
    const RSA_PADDING = OPENSSL_PKCS1_PADDING;

    private $public_key;
    private $private_key;
    private $key_len;

    public function __construct($pub_key, $pri_key = null)
    {
        $this->public_key = $pub_key;
        $this->private_key = $pri_key;

        $pub_id = openssl_get_publickey($this->public_key);
        $this->key_len = openssl_pkey_get_details($pub_id)['bits'];
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
        // The message must be no longer than the
        // length of the public modulus minus 11 bytes (taken by padding).
        $part_len = $this->key_len / 8 - 11;
        $parts = str_split($data, $part_len);

        $encrypted = '';
        foreach ($parts as $part) {
            $encrypted_temp = '';
            openssl_public_encrypt($part, $encrypted_temp, $this->public_key, self::RSA_PADDING);
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
            openssl_private_decrypt($part, $decrypted_temp, $this->private_key, self::RSA_PADDING);
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

    public function privateEncrypt($data)
    {
        // The message must be no longer than the
        // length of the public modulus minus 11 bytes (taken by padding).
        $part_len = $this->key_len / 8 - 11;
        $parts = str_split($data, $part_len);

        $encrypted = '';
        foreach ($parts as $part) {
            $encrypted_temp = '';
            openssl_private_encrypt($part, $encrypted_temp, $this->private_key, self::RSA_PADDING);
            $encrypted .= $encrypted_temp;
        }

        return url_safe_base64_encode($encrypted);
    }

    public function publicDecrypt($encrypted)
    {
        $decrypted = "";
        $part_len = $this->key_len / 8;
        $base64_decoded = url_safe_base64_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);

        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_public_decrypt($part, $decrypted_temp, $this->public_key, self::RSA_PADDING);
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

    public function sign($data)
    {
        openssl_sign($data, $sign, $this->private_key, self::RSA_ALGORITHM_SIGN);

        return url_safe_base64_encode($sign);
    }

    public function verify($data, $sign)
    {
        $pub_id = openssl_get_publickey($this->public_key);
        $res = openssl_verify($data, url_safe_base64_decode($sign), $pub_id, self::RSA_ALGORITHM_SIGN);

        return $res;
    }
}
