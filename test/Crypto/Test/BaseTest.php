<?php

namespace Crypto\Test;

use Crypto\sr25519;
use PHPUnit\Framework\TestCase;


final class BaseTest extends TestCase
{
    public function testSr25519Init ()
    {
        $sr = new sr25519();
        $pair = $sr->InitKeyPair("0x0aff680b436f6f5622f4a8030148dc4b712f02bb3b96e3dcc21ebbaeade51811");
        // public key
        $this->assertEquals("3c753c1d5859b082aa23cc7c1dc27b529c4a301dec1c06a6f650c0547901c43f", $pair->publicKey);
        // verify
        $this->assertEquals(true, $pair->VerifySign($sr->FFIInstant, "helloworld", "0x8ea7b57c28d9faf757f1606ecaf8e02baa14e9927287d2ed01f6cf8c7f86fb11bc800e10cff77d10bfd1c2d48fb522ebbb0746cbd03626578a406d6688723c88"));
    }
}