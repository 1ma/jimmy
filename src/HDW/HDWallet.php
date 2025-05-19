<?php

declare(strict_types=1);

namespace Bitcoin\HDW;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\Tx\Script;

interface HDWallet
{
    public function getAddress(int $index, bool $internal = false): string;

    public function getScriptPubKey(int $index, bool $internal = false): Script;

    public function getKey(int $index, bool $internal = false): PrivateKey;
}
