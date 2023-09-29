<?php

declare(strict_types=1);

namespace Bitcoin;

enum OpCodes: int
{
    case OP_PUSHDATA1 = 0x4C;
    case OP_PUSHDATA2 = 0x4D;
    case OP_PUSHDATA4 = 0x4E;

    case OP_IF    = 0x63;
    case OP_NOTIF = 0x64;

    case OP_VERIFY = 0x69;
    case OP_RETURN = 0x6A;

    case OP_EQUAL       = 0x87;
    case OP_EQUALVERIFY = 0x88;

    case OP_TOALTSTACK   = 0x6B;
    case OP_FROMALTSTACK = 0x6C;

    case OP_DUP = 0x76;

    case OP_HASH160 = 0xA9;
    case OP_HASH256 = 0xAA;

    case OP_CHECKSIG            = 0xAC;
    case OP_CHECKSIGVERIFY      = 0xAD;
    case OP_CHECKMULTISIG       = 0xAE;
    case OP_CHECKMULTISIGVERIFY = 0xAF;
}
