<?php

/**
 * @author williamylian
 *
 * Class Pem
 */
class Pem
{
    public static function base64ToPem($key, $type = 'PUBLIC KEY')
    {
        $pem = chunk_split($key,64,"\n"); //转换为pem格式的公钥
            return "-----BEGIN $type-----\n"
                . $pem
                . "-----END $type-----\n";
    }

    public static function pemToBase64($pem)
    {
        $parts = explode("\n", $pem);
        unset($parts[count($parts) - 1]);
        unset($parts[0]);
        return implode('', $parts);
    }
}