<?php

declare(strict_types=1);

namespace BIP32;

use Bitcoin\BIP32\CKDFunctions;
use Bitcoin\BIP32\ExtendedKey;
use PHPUnit\Framework\TestCase;

final class CKDFunctionsTest extends TestCase
{
    public function testCKDPubHardened(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $xpub = ExtendedKey::parse('xpub6CdwuTkRV7XEskhbikrbktaKLeuyiZbrFqkU17Ru4NZvitCEAdDA8AqkFwYgSLCLs33vs4JisetTxbnSZo5H6RbCccSBdpJckuPfurPmdRD');

        CKDFunctions::CKDPub($xpub->key, $xpub->chainCode, CKDFunctions::HARDENED_OFFSET);
    }

    /**
     * xpub at derivation path m/84'/0'/0' from well known BIP-39 seed 'aim x 12'.
     *
     * The expected first public key at the external and internal wallets have been
     * cross-checked with Sparrow Wallet.
     */
    public function testCKDPub(): void
    {
        $xpub = ExtendedKey::parse('xpub6CdwuTkRV7XEskhbikrbktaKLeuyiZbrFqkU17Ru4NZvitCEAdDA8AqkFwYgSLCLs33vs4JisetTxbnSZo5H6RbCccSBdpJckuPfurPmdRD');

        [$external, $chainCode] = CKDFunctions::CKDPub($xpub->key, $xpub->chainCode, 0);
        self::assertSame(
            hex2bin('03e6e2ad4cc102365a4bc2bf7e055824fca9c28b0205dbb262b2a5cd34e19fde7d'),
            CKDFunctions::CKDPub($external, $chainCode, 0)[0]->sec()
        );

        [$internal, $chainCode] = CKDFunctions::CKDPub($xpub->key, $xpub->chainCode, 1);
        self::assertSame(
            hex2bin('024b7cbabc121e401243e76c37fa3d8a0dd7901bd2486610ff75da324b3037e5b2'),
            CKDFunctions::CKDPub($internal, $chainCode, 0)[0]->sec()
        );
    }
}
