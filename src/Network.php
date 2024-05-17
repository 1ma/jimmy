<?php

declare(strict_types=1);

namespace Bitcoin;

enum Network: string
{
    case MAINNET = "\xf9\xbe\xb4\xd9";
    case REGTEST = "\xfa\xbf\xb5\xda";
    case TESTNET = "\x0b\x11\x09\x07";
}
