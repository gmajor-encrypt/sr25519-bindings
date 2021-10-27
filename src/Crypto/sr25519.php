<?php

namespace Crypto;

use FFI;

/**
 *  SR25519 Crypto lib
 *  bindings with golang go-schnorrkel  https://github.com/ChainSafe/go-schnorrkel
 *
 */
class sr25519
{
    public static function InitKeyPair ($secretSeed): keyPair
    {

        $ffi = FFI::load("src/Crypto/sr25519_lib.h");
        $keyPair = $ffi->NewKeypairFromSeed(Utils::convertGoString($ffi, $secretSeed));
        return new keyPair(FFI::string($keyPair->r0), FFI::string($keyPair->r1));
    }
}
