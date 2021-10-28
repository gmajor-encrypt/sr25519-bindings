<?php

namespace Crypto;

use FFI;

class keyPair
{
    /**
     * keyPair publicKey
     *
     * @var string $publicKey
     */
    public string $publicKey;


    /**
     * keyPair privateKey
     *
     * @var string $privateKey
     */
    protected string $privateKey;

    /**
     * keyPair construct
     *
     * @param string $pk public key
     * @param string $sk private key
     */
    public function __construct (string $pk, string $sk)
    {
        $this->privateKey = $sk;
        $this->publicKey = $pk;
    }

    /**
     *
     * Verify signature, return true if signature is correct
     *
     * @param $ffi
     * @param string $msg
     * @param string $signature
     * @return bool
     */
    public function VerifySign ($ffi, string $msg, string $signature): bool
    {

        $result = $ffi->VerifySign(
            Utils::convertGoString($ffi, $this->publicKey),
            Utils::convertGoString($ffi, $msg),
            Utils::convertGoString($ffi, $signature));
        return $ffi::string($result) == "true";
    }
}
