<?php

namespace XRsa;

/**
 *
 * Base64 for URL parameters/filenames, that adhere to RFC 4648.
 * Defaults to dropping the padding on encode since it's not required for decoding, and keeps the URL free of % encodings.
 */
if (!function_exists('base64url_encode')) {
    function base64url_encode($data, $pad = null)
    {
        $data = str_replace(array('+', '/'), array('-', '_'), base64_encode($data));
        if (!$pad) {
            $data = rtrim($data, '=');
        }
        return $data;
    }
}
if (!function_exists('base64url_decode')) {
    function base64url_decode($data)
    {
        return base64_decode(str_replace(array('-', '_'), array('+', '/'), $data));
    }
}

class XRsa
{
    const RSA_ALGORITHM_SIGN = OPENSSL_ALGO_SHA256;
    const RSA_PADDING = OPENSSL_PKCS1_PADDING;

    private $public_key;
    private $private_key;
    private $key_len;

    public function __construct(string $pub_key, string $pri_key)
    {
        $this->public_key = $pub_key;
        $this->private_key = $pri_key;

        $pub_id = openssl_get_publickey($this->public_key);
        $this->key_len = openssl_pkey_get_details($pub_id)['bits'];
    }

    public static function createKeys(int $key_size = 2048): array
    {
        $config = array(
            "private_key_bits" => $key_size,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $private_key);
        $public_key_detail = openssl_pkey_get_details($res);
        $public_key = $public_key_detail["key"];

        return [$public_key, $private_key];
    }

    public function publicEncrypt(string $data): string
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

        return base64url_encode($encrypted);
    }

    public function privateDecrypt(string $encrypted): string
    {
        $decrypted = "";
        $part_len = $this->key_len / 8;
        $base64_decoded = base64url_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);

        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_private_decrypt($part, $decrypted_temp, $this->private_key, self::RSA_PADDING);
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

    public function privateEncrypt(string $data): string
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

        return base64url_encode($encrypted);
    }

    public function publicDecrypt(string $encrypted): string
    {
        $decrypted = "";
        $part_len = $this->key_len / 8;
        $base64_decoded = base64url_decode($encrypted);
        $parts = str_split($base64_decoded, $part_len);

        foreach ($parts as $part) {
            $decrypted_temp = '';
            openssl_public_decrypt($part, $decrypted_temp, $this->public_key, self::RSA_PADDING);
            $decrypted .= $decrypted_temp;
        }
        return $decrypted;
    }

    public function sign(string $data): string
    {
        openssl_sign($data, $sign, $this->private_key, self::RSA_ALGORITHM_SIGN);

        return base64url_encode($sign);
    }

    public function verify(string $data, string $sign): bool
    {
        $pub_id = openssl_get_publickey($this->public_key);
        $res = openssl_verify($data, base64url_decode($sign), $pub_id, self::RSA_ALGORITHM_SIGN);

        return $res;
    }
}
