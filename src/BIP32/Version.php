<?php

declare(strict_types=1);

namespace Bitcoin\BIP32;

enum Version: string
{
    case MAINNET_PRIVATE = "\x04\x88\xad\xe4";
    case MAINNET_PUBLIC  = "\x04\x88\xb2\x1e";

    case TESTNET_PRIVATE = "\x04\x35\x83\x94";
    case TESTNET_PUBLIC  = "\x04\x35\x87\xcf";
}
