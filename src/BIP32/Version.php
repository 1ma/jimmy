<?php

declare(strict_types=1);

namespace Bitcoin\BIP32;

enum Version: string
{
    case MAINNET_XPRV = "\x04\x88\xad\xe4";
    case MAINNET_XPUB = "\x04\x88\xb2\x1e";

    case TESTNET_TPRV = "\x04\x35\x83\x94";
    case TESTNET_TPUB = "\x04\x35\x87\xcf";
}
