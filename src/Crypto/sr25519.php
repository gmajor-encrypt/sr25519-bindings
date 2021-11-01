<?php

namespace Crypto;

use FFI;
use InvalidArgumentException;

/**
 *  SR25519 Crypto lib
 *  is based on the same underlying curve as Ed25519. However, it uses Schnorr signatures instead of the EdDSA scheme.
 *
 *
 *  Due to the feature of ffi, currently only one instance of ffi can be init at the same time in the instance
 *
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

    /**
     * init sr25519 keyPair
     *
     * @param $secretSeed
     * (aka "Private Key" or "Raw Seed") - The minimum necessary information to restore the key pair.
     *  All other information is calculated from the seed.
     * @return keyPair
     */
    public function InitKeyPair ($secretSeed): keyPair
    {

        $data = ctype_xdigit(Utils::trimHex($secretSeed));
        if ($data === false) {
            throw new InvalidArgumentException(sprintf('"%s" is not a hex string', $secretSeed));
        }

        $ffi = $this->FFIInstant;
        $keyPair = $ffi->NewKeypairFromSeed(Utils::convertGoString($ffi, $secretSeed));
        $pk = FFI::string($keyPair);
        return new keyPair($pk, $secretSeed);
    }


    /**
     *
     * Verify signature, return true if signature is correct
     *
     * @param keyPair $pair
     * @param string $msg
     * @param string $signature
     * @return bool
     */
    public function VerifySign (keyPair $pair, string $msg, string $signature): bool
    {

        $result = $this->FFIInstant->VerifySign(
            Utils::convertGoString($this->FFIInstant, $pair->publicKey),
            Utils::convertGoString($this->FFIInstant, $msg),
            Utils::convertGoString($this->FFIInstant, $signature));
        return $this->FFIInstant::string($result) == "true";
    }


    /**
     *
     * Sign uses the private key to sign the message using the sr25519 signature algorithm
     *
     * @param keyPair $pair
     * @param string $msg
     * @return string
     */
    public function Sign (keyPair $pair, string $msg): string
    {
        return $pair->sign($this->FFIInstant, $msg);
    }
}
