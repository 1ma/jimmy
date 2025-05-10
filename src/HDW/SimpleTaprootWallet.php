<?php

declare(strict_types=1);

namespace Bitcoin\HDW;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\S256Point;
use Bitcoin\Encoding\Bech32;
use Bitcoin\Hashing;
use Bitcoin\Tx\Script;

final readonly class SimpleTaprootWallet
{
    public ExtendedKey $account;

    public function __construct(ExtendedKey $bip32root, int $account)
    {
        if (!$bip32root->key instanceof PrivateKey) {
            throw new \InvalidArgumentException('bip32root needs to be an extended private key');
        }

        $coin = Version::MAINNET_XPRV === $bip32root->version ? 0 : 1;

        $this->account = DerivationPath::parse("m/86'/{$coin}'/{$account}'")->derive($bip32root);
    }

    public function getAddress(int $index, bool $internal = false): string
    {
        $script = $this->getScriptPubKey($index, $internal);
        $hrp    = Version::MAINNET_XPRV === $this->account->version ? Bech32::MAINNET_HRP : Bech32::TESTNET_HRP;

        return Bech32::segwitEncode(1, unpack('C*', $script->cmds[1]), $hrp);
    }

    public function getScriptPubKey(int $index, bool $internal = false): Script
    {
        $change = $internal ? 1 : 0;
        $subkey = DerivationPath::parse("m/{$change}/{$index}")->derive($this->account);

        $internalKey = S256Point::liftX($subkey->key->pubKey->x->num);

        $tweak      = Hashing::taggedHash('TapTweak', $internalKey->xonly());
        $tweakedKey = $internalKey->tweak(gmp_import($tweak));

        return Script::payToSegWitV1($tweakedKey);
    }
}
