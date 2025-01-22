<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script;

enum OpCodes: int
{
    case OP_0 = 0x00;

    case OP_PUSHDATA1 = 0x4C;
    case OP_PUSHDATA2 = 0x4D;
    case OP_PUSHDATA4 = 0x4E;

    case OP_1  = 0x51;
    case OP_2  = 0x52;
    case OP_3  = 0x53;
    case OP_4  = 0x54;
    case OP_5  = 0x55;
    case OP_6  = 0x56;
    case OP_7  = 0x57;
    case OP_8  = 0x58;
    case OP_9  = 0x59;
    case OP_10 = 0x5A;
    case OP_11 = 0x5B;
    case OP_12 = 0x5C;
    case OP_13 = 0x5D;
    case OP_14 = 0x5E;
    case OP_15 = 0x5F;
    case OP_16 = 0x60;

    case OP_IF    = 0x63;
    case OP_NOTIF = 0x64;

    case OP_VERIFY = 0x69;

    case OP_RETURN       = 0x6A;
    case OP_TOALTSTACK   = 0x6B;
    case OP_FROMALTSTACK = 0x6C;
    case OP_2DROP        = 0x6D;
    case OP_2DUP         = 0x6E;
    case OP_3DUP         = 0x6F;

    case OP_DROP = 0x75;
    case OP_DUP  = 0x76;

    case OP_SWAP = 0x7C;

    case OP_EQUAL       = 0x87;
    case OP_EQUALVERIFY = 0x88;

    case OP_NOT       = 0x91;
    case OP_0NOTEQUAL = 0x92;
    case OP_ADD       = 0x93;

    case OP_RIPEMD160 = 0xA6;
    case OP_SHA1      = 0xA7;
    case OP_SHA256    = 0xA8;
    case OP_HASH160   = 0xA9;
    case OP_HASH256   = 0xAA;

    case OP_CHECKSIG            = 0xAC;
    case OP_CHECKSIGVERIFY      = 0xAD;
    case OP_CHECKMULTISIG       = 0xAE;
    case OP_CHECKMULTISIGVERIFY = 0xAF;

    case OP_CHECKLOCKTIMEVERIFY = 0xB1;
    case OP_CHECKSEQUENCEVERIFY = 0xB2;
}
