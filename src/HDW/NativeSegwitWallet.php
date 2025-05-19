<?php

declare(strict_types=1);

namespace Bitcoin\HDW;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\Encoding\Address;
use Bitcoin\Hashing;
use Bitcoin\Network;
use Bitcoin\Tx\Script;

final readonly class NativeSegwitWallet implements HDWallet
{
    public ExtendedKey $account;

    public function __construct(ExtendedKey $bip32root, int $account)
    {
        if (!$bip32root->key instanceof PrivateKey) {
            throw new \InvalidArgumentException('bip32root needs to be an extended private key');
        }

        $coin = Version::MAINNET_XPRV === $bip32root->version ? 0 : 1;

        $this->account = DerivationPath::parse("m/84'/{$coin}'/{$account}'")->derive($bip32root);
    }

    public function getAddress(int $index, bool $internal = false): string
    {
        $mode = Version::MAINNET_XPRV === $this->account->version ? Network::MAINNET : Network::TESTNET;

        return Address::p2wpkh($this->getKey($index, $internal)->pubKey, $mode);
    }

    public function getScriptPubKey(int $index, bool $internal = false): Script
    {
        return Script::payToSegWitV0(Hashing::hash160($this->getKey($index, $internal)->pubKey->sec(true)));
    }

    public function getKey(int $index, bool $internal = false): PrivateKey
    {
        $change = $internal ? 1 : 0;

        return DerivationPath::parse("m/{$change}/{$index}")->derive($this->account)->key;
    }
}
