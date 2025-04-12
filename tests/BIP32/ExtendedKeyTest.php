<?php

declare(strict_types=1);

namespace Bitcoin\Tests\BIP32;

use Bitcoin\BIP32\DerivationPath;
use Bitcoin\BIP32\ExtendedKey;
use Bitcoin\BIP32\Version;
use Bitcoin\ECC\PrivateKey;
use PHPUnit\Framework\Attributes\DataProvider;
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
        self::assertSame('ca87cc91', $tprv->fingerprint());

        $tpub = ExtendedKey::parse('tpubDDLahZuFszwU6P4hEiJJ5tWaSrCvFoH2CBCuC5uCPyNaNnVMYZqTLH78pygnw4JajScUM3NoesTQ2FWhKFD4ii5F6rV8vwWgTmFWHjY9KAx');

        self::assertSame(Version::TESTNET_PUBLIC, $tpub->version);
        self::assertSame(3, $tpub->depth);
        self::assertSame('b2b42ad1', $tpub->parentFingerprint);
        self::assertSame(0x80000000, $tpub->childNumber);
        self::assertSame(hex2bin('789d9574ca338deaa5f94427e1ae3bfe8f4d15072f315688a4694b6cccc17c5b'), $tpub->chainCode);
        self::assertSame(hex2bin('0213f2598b6676306789beac36c86d2f38b5d4fd8b707a297377de0906c7428ee3'), $tpub->key->sec());
        self::assertSame('124f1aba', $tpub->fingerprint());
    }

    #[DataProvider('Bip32TestVector1Provider')]
    public function testBip32TestVector1(
        string $path,
        int $depth,
        string $parentFingerprint,
        int $childNumber,
        string $expectedXPrv,
        string $expectedXPub,
        string $expectedFingerprint,
    ): void {
        $seed            = hex2bin('000102030405060708090a0b0c0d0e0f');
        $I               = hash_hmac('sha512', $seed, 'Bitcoin seed', true);
        $masterKey       = new PrivateKey(gmp_import(substr($I, 0, 32)));
        $masterChainCode = substr($I, 32, 32);

        $derivationPath           = DerivationPath::parse($path);
        [$privateKey, $chainCode] = $derivationPath->derive($masterKey, $masterChainCode);
        $xprv                     = new ExtendedKey(Version::MAINNET_PRIVATE, $depth, $parentFingerprint, $childNumber, $chainCode, $privateKey);
        self::assertSame($expectedXPrv, (string) $xprv);
        self::assertSame($expectedFingerprint, $xprv->fingerprint());

        $xpub = new ExtendedKey(Version::MAINNET_PUBLIC, $depth, $parentFingerprint, $childNumber, $chainCode, $privateKey->pubKey);
        self::assertSame($expectedXPub, (string) $xpub);
        self::assertSame($expectedFingerprint, $xpub->fingerprint());
    }

    public static function Bip32TestVector1Provider(): array
    {
        return [
            'Chain m' => [
                'm',
                0,
                '00000000',
                0,
                'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
                'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
                '3442193e',
            ],
            'Chain m/0h' => [
                "m/0'",
                1,
                '3442193e',
                0x80000000,
                'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
                'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
                '5c1bd648',
            ],
            'Chain m/0h/1' => [
                "m/0'/1",
                2,
                '5c1bd648',
                1,
                'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',
                'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
                'bef5a2f9',
            ],
            'Chain m/0h/1/2h' => [
                "m/0'/1/2'",
                3,
                'bef5a2f9',
                0x80000000 + 2,
                'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',
                'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
                'ee7ab90c',
            ],
            'Chain m/0h/1/2h/2' => [
                "m/0'/1/2'/2",
                4,
                'ee7ab90c',
                2,
                'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',
                'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
                'd880d7d8',
            ],
            'Chain m/0h/1/2h/2/1000000000' => [
                "m/0'/1/2'/2/1000000000",
                5,
                'd880d7d8',
                1000000000,
                'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
                'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
                'd69aa102',
            ],
        ];
    }
}
