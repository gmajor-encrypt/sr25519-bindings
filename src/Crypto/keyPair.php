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
    private string $privateKey;

    /**
     * keyPair construct
     *
     * @param string $pk Public key
     * @param string $sk Secret seed
     */
    public function __construct (string $pk, string $sk)
    {
        $this->privateKey = $sk;
        $this->publicKey = $pk;
    }

    /**
     * @param void $ffi FFI instant
     * @param string $msg
     * @return string
     */
    public function sign ($ffi, string $msg): string
    {
        $result = $ffi->Sign(
            Utils::convertGoString($ffi, $this->privateKey),
            Utils::convertGoString($ffi, $msg));
        return "0x" . $ffi::string($result);
    }
}


