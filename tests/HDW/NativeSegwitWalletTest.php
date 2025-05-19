<?php

declare(strict_types=1);

namespace Bitcoin\Tests\HDW;

use Bitcoin\HDW\ExtendedKey;
use Bitcoin\HDW\Mnemonic;
use Bitcoin\HDW\NativeSegwitWallet;
use PHPUnit\Framework\TestCase;

final class NativeSegwitWalletTest extends TestCase
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

        $wallet = new NativeSegwitWallet($bip32RootKey, 0);
        self::assertSame('xprv9ybY78BftS5UGANki6oSifuQEjkpyAC8ZmBvBNTshQnCBcxnefjHS7buPMkkqhcRzmoGZ5bokx7GuyDAiktd5HemohAU4wV1ZPMDRmLpBMm', $wallet->account->serialize());
        self::assertSame('xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V', $wallet->account->xpub()->serialize());

        $firstScript  = $wallet->getScriptPubKey(0, internal: false);
        $firstAddress = $wallet->getAddress(0, internal: false);
        self::assertSame(hex2bin('160014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2'), $firstScript->serialize());
        self::assertSame('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', $firstAddress);

        $secondScript  = $wallet->getScriptPubKey(1, internal: false);
        $secondAddress = $wallet->getAddress(1, internal: false);
        self::assertSame(hex2bin('1600149c90f934ea51fa0f6504177043e0908da6929983'), $secondScript->serialize());
        self::assertSame('bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g', $secondAddress);

        $firstChangeScript  = $wallet->getScriptPubKey(0, internal: true);
        $firstChangeAddress = $wallet->getAddress(0, internal: true);
        self::assertSame(hex2bin('1600143e34985dca6fddc9fb369940e4c7d8e2873f529c'), $firstChangeScript->serialize());
        self::assertSame('bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el', $firstChangeAddress);
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

        new NativeSegwitWallet($bip32RootKey->xpub(), 0);
    }
}
