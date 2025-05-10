<?php

declare(strict_types=1);

namespace Bitcoin\Tests\HDW;

use Bitcoin\HDW\ExtendedKey;
use Bitcoin\HDW\Mnemonic;
use Bitcoin\HDW\SimpleTaprootWallet;
use PHPUnit\Framework\TestCase;

final class SimpleTaprootWalletTest extends TestCase
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

        $wallet = new SimpleTaprootWallet($bip32RootKey, 0);
        self::assertSame('xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk', $wallet->account->serialize());
        self::assertSame('xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ', $wallet->account->xpub()->serialize());

        $firstScript  = $wallet->getScriptPubKey(0, internal: false);
        $firstAddress = $wallet->getAddress(0, internal: false);
        self::assertSame(hex2bin('225120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c'), $firstScript->serialize());
        self::assertSame('bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', $firstAddress);

        $secondScript  = $wallet->getScriptPubKey(1, internal: false);
        $secondAddress = $wallet->getAddress(1, internal: false);
        self::assertSame(hex2bin('225120a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb'), $secondScript->serialize());
        self::assertSame('bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh', $secondAddress);

        $firstChangeScript  = $wallet->getScriptPubKey(0, internal: true);
        $firstChangeAddress = $wallet->getAddress(0, internal: true);
        self::assertSame(hex2bin('225120882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc'), $firstChangeScript->serialize());
        self::assertSame('bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7', $firstChangeAddress);
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

        new SimpleTaprootWallet($bip32RootKey->xpub(), 0);
    }
}
