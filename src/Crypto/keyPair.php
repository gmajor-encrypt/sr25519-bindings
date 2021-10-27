<?php

namespace Crypto;

class keyPair
{
    /**
     * keyPair publicKey
     *
     * @var $publicKey
     */
    public $publicKey;


    /**
     * keyPair privateKey
     *
     * @var $privateKey
     */
    protected $privateKey;

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

}
