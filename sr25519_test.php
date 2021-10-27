<?php

$ffi = FFI::load("sr25519_lib.h");

$str = "0x0aff680b436f6f5622f4a8030148dc4b712f02bb3b96e3dcc21ebbaeade51811";
$goStr = $ffi->new('GoString', 0);
$size = strlen($str);
$cStr = FFI::new("char[$size]", 0);

FFI::memcpy($cStr, $str, $size);
$goStr->p = $cStr;
$goStr->n = strlen($str);
$pair = $ffi->NewKeypairFromSeed($goStr);

assert(FFI::string($pair->r0) == "99076b413982a5de4433a600b1e8321dda4f84235fc458c0aea2c7787fdfa90f");

assert(FFI::string($pair->r1) == "3c753c1d5859b082aa23cc7c1dc27b529c4a301dec1c06a6f650c0547901c43f");


