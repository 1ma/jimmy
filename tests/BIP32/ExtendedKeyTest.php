<?php

declare(strict_types=1);

namespace Bitcoin\Tests\BIP32;

use Bitcoin\BIP32\DerivationPath;
use Bitcoin\BIP32\ExtendedKey;
use Bitcoin\BIP32\Version;
use Bitcoin\ECC\PrivateKey;
use Bitcoin\Hashing;
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

        self::assertSame(Version::TESTNET_TPRV, $tprv->version);
        self::assertSame(0, $tprv->depth);
        self::assertSame('00000000', $tprv->parentFingerprint);
        self::assertSame(0, $tprv->childNumber);
        self::assertSame(hex2bin('8cfa330c3e1e2e5428b5c9c6e4b13790843aa2b7c668d8dca9001783d60e4bc8'), $tprv->chainCode);
        self::assertSame(hex2bin('b795b541cb4f44239a18e01d6ddc676547364ed845e0ac61a16945d82ad5915f'), gmp_export($tprv->key->secret));
        self::assertSame('ca87cc91', $tprv->fingerprint());

        $tpub = ExtendedKey::parse('tpubDDLahZuFszwU6P4hEiJJ5tWaSrCvFoH2CBCuC5uCPyNaNnVMYZqTLH78pygnw4JajScUM3NoesTQ2FWhKFD4ii5F6rV8vwWgTmFWHjY9KAx');

        self::assertSame(Version::TESTNET_TPUB, $tpub->version);
        self::assertSame(3, $tpub->depth);
        self::assertSame('b2b42ad1', $tpub->parentFingerprint);
        self::assertSame(0x80000000, $tpub->childNumber);
        self::assertSame(hex2bin('789d9574ca338deaa5f94427e1ae3bfe8f4d15072f315688a4694b6cccc17c5b'), $tpub->chainCode);
        self::assertSame(hex2bin('0213f2598b6676306789beac36c86d2f38b5d4fd8b707a297377de0906c7428ee3'), $tpub->key->sec());
        self::assertSame('124f1aba', $tpub->fingerprint());
    }

    #[DataProvider('Bip32ValidTestVectorsProvider')]
    public function testBip32ValidTestVectors(
        string $seed,
        string $path,
        string $parentFingerprint,
        string $expectedXPrv,
        string $expectedXPub,
        string $expectedFingerprint,
    ): void {
        $I               = Hashing::sha512hmac(hex2bin($seed), 'Bitcoin seed');
        $masterKey       = new PrivateKey(gmp_import(substr($I, 0, 32)));
        $masterChainCode = substr($I, 32, 32);

        $path                     = DerivationPath::parse($path);
        [$privateKey, $chainCode] = $path->derive($masterKey, $masterChainCode);

        $xprv = new ExtendedKey(Version::MAINNET_XPRV, $path->depth(), $parentFingerprint, $path->childNumber(), $chainCode, $privateKey);
        self::assertSame($expectedXPrv, (string) $xprv);
        self::assertSame($expectedFingerprint, $xprv->fingerprint());

        $xpub = new ExtendedKey(Version::MAINNET_XPUB, $path->depth(), $parentFingerprint, $path->childNumber(), $chainCode, $privateKey->pubKey);
        self::assertSame($expectedXPub, (string) $xpub);
        self::assertSame($xprv->fingerprint(), $xpub->fingerprint());
    }

    public static function Bip32ValidTestVectorsProvider(): array
    {
        return [
            'Test Vector 1, Chain m' => [
                '000102030405060708090a0b0c0d0e0f',
                'm',
                '00000000',
                'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
                'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
                '3442193e',
            ],
            'Test Vector 1, Chain m/0h' => [
                '000102030405060708090a0b0c0d0e0f',
                "m/0'",
                '3442193e',
                'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
                'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
                '5c1bd648',
            ],
            'Test Vector 1, Chain m/0h/1' => [
                '000102030405060708090a0b0c0d0e0f',
                "m/0'/1",
                '5c1bd648',
                'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',
                'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
                'bef5a2f9',
            ],
            'Test Vector 1, Chain m/0h/1/2h' => [
                '000102030405060708090a0b0c0d0e0f',
                "m/0'/1/2'",
                'bef5a2f9',
                'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',
                'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
                'ee7ab90c',
            ],
            'Test Vector 1, Chain m/0h/1/2h/2' => [
                '000102030405060708090a0b0c0d0e0f',
                "m/0'/1/2'/2",
                'ee7ab90c',
                'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',
                'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
                'd880d7d8',
            ],
            'Test Vector 1, Chain m/0h/1/2h/2/1000000000' => [
                '000102030405060708090a0b0c0d0e0f',
                "m/0'/1/2'/2/1000000000",
                'd880d7d8',
                'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
                'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
                'd69aa102',
            ],
            'Test Vector 2, Chain m' => [
                'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
                'm',
                '00000000',
                'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
                'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
                'bd16bee5',
            ],
            'Test Vector 2, Chain m/0' => [
                'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
                'm/0',
                'bd16bee5',
                'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt',
                'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
                '5a61ff8e',
            ],
            'Test Vector 2, Chain m/0/2147483647h' => [
                'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
                "m/0/2147483647'",
                '5a61ff8e',
                'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',
                'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
                'd8ab4937',
            ],
            'Test Vector 2, Chain m/0/2147483647h/1' => [
                'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
                "m/0/2147483647'/1",
                'd8ab4937',
                'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef',
                'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
                '78412e3a',
            ],
            'Test Vector 2, Chain m/0/2147483647h/1/2147483646h' => [
                'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
                "m/0/2147483647'/1/2147483646'",
                '78412e3a',
                'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc',
                'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
                '31a507b8',
            ],
            'Test Vector 2, Chain m/0/2147483647h/1/2147483646h/2' => [
                'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
                "m/0/2147483647'/1/2147483646'/2",
                '31a507b8',
                'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j',
                'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
                '26132fdb',
            ],
            'Test Vector 3, Chain m' => [
                '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
                'm',
                '00000000',
                'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
                'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',
                '41d63b50',
            ],
            'Test Vector 3, Chain m/0h' => [
                '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be',
                "m/0'",
                '41d63b50',
                'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L',
                'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
                'c61368bb',
            ],
            'Test Vector 4, Chain m' => [
                '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678',
                'm',
                '00000000',
                'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv',
                'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa',
                'ad85d955',
            ],
            'Test Vector 4, Chain m/0h' => [
                '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678',
                "m/0'",
                'ad85d955',
                'xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G',
                'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m',
                'cfa61281',
            ],
            'Test Vector 4, Chain m/0h/1h' => [
                '3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678',
                "m/0'/1'",
                'cfa61281',
                'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1',
                'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt',
                '48b2a626',
            ],
        ];
    }

    #[DataProvider('Bip32TestVector5Provider')]
    public function testBip32TestVector5(string $invalidKey): void
    {
        $this->expectException(\InvalidArgumentException::class);

        ExtendedKey::parse($invalidKey);
    }

    public static function Bip32TestVector5Provider(): array
    {
        return [
            'pubkey version / prvkey mismatch'                 => ['xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm'],
            'prvkey version / pubkey mismatch'                 => ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH'],
            'invalid pubkey prefix 04'                         => ['xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn'],
            'invalid prvkey prefix 04'                         => ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ'],
            'invalid pubkey prefix 01'                         => ['xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4'],
            'invalid prvkey prefix 01'                         => ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J'],
            'zero depth xprv with non-zero parent fingerprint' => ['xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv'],
            'zero depth xpub with non-zero parent fingerprint' => ['xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ'],
            'zero depth xprv with non-zero index'              => ['xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN'],
            'zero depth xpub with non-zero index'              => ['xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8'],
            'unknown extended key version 1'                   => ['DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4'],
            'unknown extended key version 2'                   => ['DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9'],
            'private key 0 not in 1..n-1'                      => ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx'],
            'private key n not in 1..n-1'                      => ['xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G'],
            'invalid public key'                               => ['xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY'],
            'invalid checksum'                                 => ['xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL'],
        ];
    }
}
