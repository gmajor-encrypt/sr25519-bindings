<?php

namespace Crypto;

use FFI;

/**
 * Utils package various tool functions
 *
 * Class Utils
 *
 * @package Codec
 */
class Utils
{

    /**
     *
     * Unpack data from a binary string
     *
     * @param string $str
     * @return array|false
     */
    public static function string2ByteArray (string $str)
    {
        return unpack('C*', $str);
    }


    /**
     * Bytes data to string
     *
     * @param $bytes
     * @return string
     */
    public static function byteArray2String ($bytes): string
    {
        $chars = array_map("chr", $bytes);
        return join($chars);
    }

    /**
     * bytes data to hex string
     *
     * @param array $bytes
     * @return string
     */
    public static function bytesToHex (array $bytes): string
    {
        $chars = array_map("chr", $bytes);
        $bin = join($chars);
        return bin2hex($bin);
    }

    /**
     * hex string to bytes data
     *
     * @param $hex
     * @return array
     */
    public static function hexToBytes ($hex): array
    {
        $string = hex2bin($hex);
        $value = unpack('C*', $string);
        return is_array($value) ? array_values($value) : [];
    }

    /**
     * Convert binary data into hexadecimal representation
     *
     * @param string $string
     * @return string
     */
    public static function string2Hex (string $string): string
    {
        return bin2hex($string);
    }

    /**
     *  Convert hexadecimal string to its binary representation.
     *
     * @param string $hexString
     * @return bool|string
     */
    public static function hex2String (string $hexString)
    {
        return hex2bin($hexString);
    }


    /**
     *  trim hex prefix 0x
     *
     * @param $hexString string
     * @return string|string[]|null
     */
    public static function trimHex (string $hexString)
    {
        return preg_replace('/0x/', '', $hexString);
    }

    /**
     * convert php string to go string
     *
     * @param void $ffi ffi instant
     * @param string $str
     * @return mixed
     */
    public static function convertGoString ($ffi, string $str)
    {
        $goStr = $ffi->new('GoString', 0);
        $size = strlen($str);
        $cStr = FFI::new("char[$size]", 0);
        FFI::memcpy($cStr, $str, $size);
        $goStr->p = $cStr;
        $goStr->n = strlen($str);
        return $goStr;
    }

}
