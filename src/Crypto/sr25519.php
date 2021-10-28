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
    /**
     * @var $FFIInstant
     */
    public $FFIInstant;

    public function __construct ()
    {
        $this->FFIInstant = FFI::load("src/Crypto/sr25519_lib.h");
    }


    public function InitKeyPair ($secretSeed): keyPair
    {

        $ffi = $this->FFIInstant;
        $keyPair = $ffi->NewKeypairFromSeed(Utils::convertGoString($ffi, $secretSeed));
        $pk = FFI::string($keyPair);
        return new keyPair($pk, $secretSeed);
    }

}
