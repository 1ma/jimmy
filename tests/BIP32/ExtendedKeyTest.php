<?php

declare(strict_types=1);

namespace Bitcoin\Tests\BIP32;

use Bitcoin\BIP32\ExtendedKey;
use Bitcoin\BIP32\Version;
use PHPUnit\Framework\TestCase;

final class ExtendedKeyTest extends TestCase
{
    /**
     * This extended private key has been randomly generated at https://iancoleman.io/bip39/
     * The extended public key is the result of importing the tprv into Sparrow as a P2WPKH wallet (m/84'/1'/0').
     */
    public function testOneCase(): void
    {
        $tprv = ExtendedKey::parse('tprv8ZgxMBicQKsPeGzpnH2ttAuasJdFYddkhaxBADnFLMzfNwafbZQYdd4ar4knzAfqzYJWHDEwHaqHY3qDXqhFBB4ymsLfXsMPYYuRVXGWwSG');

        self::assertSame(Version::TESTNET_PRIVATE, $tprv->version);
        self::assertSame(0, $tprv->depth);
        self::assertSame('00000000', $tprv->parentFingerprint);
        self::assertSame(0, $tprv->childNumber);
        self::assertSame(hex2bin('8cfa330c3e1e2e5428b5c9c6e4b13790843aa2b7c668d8dca9001783d60e4bc8'), $tprv->chainCode);
        self::assertSame(hex2bin('b795b541cb4f44239a18e01d6ddc676547364ed845e0ac61a16945d82ad5915f'), gmp_export($tprv->key->secret));

        $tpub = ExtendedKey::parse('tpubDDLahZuFszwU6P4hEiJJ5tWaSrCvFoH2CBCuC5uCPyNaNnVMYZqTLH78pygnw4JajScUM3NoesTQ2FWhKFD4ii5F6rV8vwWgTmFWHjY9KAx');

        self::assertSame(Version::TESTNET_PUBLIC, $tpub->version);
        self::assertSame(3, $tpub->depth);
        self::assertSame('b2b42ad1', $tpub->parentFingerprint);
        self::assertSame(0x80000000, $tpub->childNumber);
        self::assertSame(hex2bin('789d9574ca338deaa5f94427e1ae3bfe8f4d15072f315688a4694b6cccc17c5b'), $tpub->chainCode);
        self::assertSame(hex2bin('0213f2598b6676306789beac36c86d2f38b5d4fd8b707a297377de0906c7428ee3'), $tpub->key->sec());
    }
}
