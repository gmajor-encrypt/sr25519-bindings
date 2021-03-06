<?php

namespace Crypto\Test;

use Crypto\sr25519;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;

final class BaseTest extends TestCase
{

    /**
     *
     * test
     *
     * @depends  testSr25519FFIProvider
     */
    public function testSr2551KeyPair9Init (sr25519 $sr)
    {
        $pair = $sr->InitKeyPair("0x0aff680b436f6f5622f4a8030148dc4b712f02bb3b96e3dcc21ebbaeade51811");
        // public key
        $this->assertEquals("3c753c1d5859b082aa23cc7c1dc27b529c4a301dec1c06a6f650c0547901c43f", $pair->publicKey);
        // test empty seed
        $this->expectException(InvalidArgumentException::class);
        $sr->InitKeyPair("");
    }

    /**
     * @depends  testSr25519FFIProvider
     */
    public function testSr25519SignatureVerify (sr25519 $sr)
    {
        $pair = $sr->InitKeyPair("0x0aff680b436f6f5622f4a8030148dc4b712f02bb3b96e3dcc21ebbaeade51811");
        // Passed Verify
        $this->assertEquals(true, $sr->VerifySign($pair, "helloworld", "0x8ea7b57c28d9faf757f1606ecaf8e02baa14e9927287d2ed01f6cf8c7f86fb11bc800e10cff77d10bfd1c2d48fb522ebbb0746cbd03626578a406d6688723c88"));
        // Verify failed
        $this->assertEquals(false, $sr->VerifySign($pair, "hel", "0x4053b868e50e1685fd011df37fbeab603de0181beddeaa210d889244d11c5f3030d9fd7ce24d80207272e09be89fe6361a0bef1cce1e830f391e68cb4a879182"));
    }


    /**
     * @depends  testSr25519FFIProvider
     */
    public function testSr25519Sign (sr25519 $sr)
    {
        $pair = $sr->InitKeyPair("0x0aff680b436f6f5622f4a8030148dc4b712f02bb3b96e3dcc21ebbaeade51811");
        // sign utf8 msg
        $this->assertEquals(true, $sr->VerifySign($pair, "helloworld", $sr->Sign($pair, "helloworld")));
        // sign hex msg
        $this->assertEquals(true, $sr->VerifySign($pair, "0xaeade51811", $sr->Sign($pair, "0xaeade51811")));
        // sign empty msg
        $this->assertEquals(true, $sr->VerifySign($pair, "", $sr->Sign($pair, "")));
    }


    /**
     * test XXHash64 hash
     *
     * @depends  testSr25519FFIProvider
     */
    public function testXXHash64 (sr25519 $sr)
    {
        $this->assertEquals("398167db5dcadc4f",$sr->XXHash64CheckSum(0,"test"));
        $this->assertEquals("8d3e46a2f8c36954",$sr->XXHash64CheckSum(0,"0xffff"));
        $this->assertEquals("69f126323530963c",$sr->XXHash64CheckSum(1,"0xffffffff"));
        $this->assertEquals("f1750113e3b35e95",$sr->XXHash64CheckSum(16,"0xffffffff"));
        $this->assertEquals("444bd0c234de5108",$sr->XXHash64CheckSum(32,"0xfffffffffffff"));
    }

    /**
     * provider sr25519 ffi
     *
     * @return sr25519
     */
    public function testSr25519FFIProvider (): sr25519
    {
        $sr = new sr25519();
        $this->assertNotNull($sr->FFIInstant);
        return $sr;
    }

}