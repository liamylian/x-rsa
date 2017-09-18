<?php

namespace XRsa;

class Crypt
{
    private $key;

    public function __construct($key)
    {
        $this->key = $key;
    }

    public function encrypt($str)
    {
        $r = md5($this->key);
        $c = 0;
        $v = "";
        $len = strlen($str);
        $l = strlen($r);
        for ($i = 0; $i < $len; $i++) {
            if ($c == $l) $c = 0;
            $v .= substr($r, $c, 1) .
                (substr($str, $i, 1) ^ substr($r, $c, 1));
            $c++;
        }

        return self::ed($v, $this->key);
    }

    public function decrypt($str)
    {
        $str = self::ed($str, $this->key);

        $v = "";
        $len = strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $md5 = substr($str, $i, 1);
            $i++;
            $v .= (substr($str, $i, 1) ^ $md5);
        }
        return $v;
    }

    private static function ed($str, $key)
    {
        $r = md5($key);
        $c = 0;
        $v = "";
        $len = strlen($str);
        $l = strlen($r);
        for ($i = 0; $i < $len; $i++) {
            if ($c == $l) $c = 0;
            $v .= substr($str, $i, 1) ^ substr($r, $c, 1);
            $c++;
        }
        return $v;
    }
}