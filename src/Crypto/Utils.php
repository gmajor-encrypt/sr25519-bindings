<?php

namespace Crypto;

use FFI;

/**
 * Utils package various tool functions
 *
 * Class Utils
 *
 * @package Crypto
 */
class Utils
{

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
        if($str == ""){
            return $goStr;
        }
        $size = strlen($str);
        $cStr = FFI::new("char[$size]", 0);
        FFI::memcpy($cStr, $str, $size);
        $goStr->p = $cStr;
        $goStr->n = strlen($str);
        return $goStr;
    }

}
