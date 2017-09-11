<?php

if (! function_exists('url_safe_base64_encode')) {
    function url_safe_base64_encode ($data) {
        return str_replace(array('+','/', '='),array('-','_', ''), base64_encode($data));
    }
}

if (! function_exists('url_safe_base64_decode')) {
    function url_safe_base64_decode ($data) {
        $base_64 = str_replace(array('-','_'),array('+','/'), $data);
        return base64_decode($base_64);
    }
}

if (! function_exists('base64_to_url_safe_base64')) {
    function base64_to_url_safe_base64 ($data) {
        return str_replace(array('+', '/', '='),array('-', '_', ''), $data);
    }
}

if (! function_exists('url_safe_base64_to_base64')) {
    function url_safe_base64_to_base64 ($data) {
        return str_replace(array('-','_'),array('+','/'), $data);
    }
}
