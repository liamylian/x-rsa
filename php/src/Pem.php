<?php

namespace XRsa;

/**
 * @author williamylian
 *
 * Class Pem
 */
class Pem
{
    public static function base64ToPem($key, $is_public = true)
    {
        $pem = chunk_split($key,64,"\n"); //转换为pem格式的公钥
        if ($is_public) {
            return "-----BEGIN PUBLIC KEY-----\n".$pem."-----END PUBLIC KEY-----\n";
        } else {
            return "-----BEGIN PRIVATE KEY-----\n".$pem."-----END PRIVATE KEY-----\n";
        }
    }

    public static function PemToBase64($pem)
    {
        $parts = explode("\n", $pem);
        unset($parts[count($parts) - 1]);
        unset($parts[0]);
        return implode('', $parts);
    }
}