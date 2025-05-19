<?php

declare(strict_types=1);

namespace Bitcoin\Tests\HDW;

use Bitcoin\HDW\ExtendedKey;
use Bitcoin\HDW\LegacyWallet;
use Bitcoin\HDW\Mnemonic;
use PHPUnit\Framework\TestCase;

final class LegacyWalletTest extends TestCase
{
    public function testBip86Vectors(): void
    {
        $mnemonic = [
            'abandon', 'abandon', 'abandon', 'abandon',
            'abandon', 'abandon', 'abandon', 'abandon',
            'abandon', 'abandon', 'abandon', 'about',
        ];

        $bip32RootKey = ExtendedKey::create(Mnemonic::deriveSeed($mnemonic), mainnet: true);
        self::assertSame('xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu', $bip32RootKey->serialize());
        self::assertSame('xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8', $bip32RootKey->xpub()->serialize());

        $wallet = new LegacyWallet($bip32RootKey, 0);
        self::assertSame('xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb', $wallet->account->serialize());
        self::assertSame('xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj', $wallet->account->xpub()->serialize());

        $firstScript  = $wallet->getScriptPubKey(0, internal: false);
        $firstAddress = $wallet->getAddress(0, internal: false);
        self::assertSame(hex2bin('1976a914d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa88ac'), $firstScript->serialize());
        self::assertSame('1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA', $firstAddress);

        $secondScript  = $wallet->getScriptPubKey(1, internal: false);
        $secondAddress = $wallet->getAddress(1, internal: false);
        self::assertSame(hex2bin('1976a9146ae1301cf44ca525751d1763ac4fef12d115398688ac'), $secondScript->serialize());
        self::assertSame('1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP', $secondAddress);

        $firstChangeScript  = $wallet->getScriptPubKey(0, internal: true);
        $firstChangeAddress = $wallet->getAddress(0, internal: true);
        self::assertSame(hex2bin('1976a914bae93c8e7fb682422d24780b1a12a550eff428f288ac'), $firstChangeScript->serialize());
        self::assertSame('1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH', $firstChangeAddress);
    }

    public function testInvalidBip32RootKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $mnemonic = [
            'abandon', 'abandon', 'abandon', 'abandon',
            'abandon', 'abandon', 'abandon', 'abandon',
            'abandon', 'abandon', 'abandon', 'about',
        ];

        $bip32RootKey = ExtendedKey::create(Mnemonic::deriveSeed($mnemonic), mainnet: true);

        new LegacyWallet($bip32RootKey->xpub(), 0);
    }
}
