<?php

namespace Crypto\Test;

use Crypto\sr25519;
use PHPUnit\Framework\TestCase;


final class BaseTest extends TestCase
{
    public function testKeyPairInit ()
    {
        $pair = sr25519::InitKeyPair("0x0aff680b436f6f5622f4a8030148dc4b712f02bb3b96e3dcc21ebbaeade51811");
        $this->assertEquals($pair->publicKey, "99076b413982a5de4433a600b1e8321dda4f84235fc458c0aea2c7787fdfa90f");
    }
}