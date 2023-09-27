<?php

declare(strict_types=1);

namespace Bitcoin;

enum OpCodes: int
{
    case OP_PUSHDATA1 = 0x4C;
    case OP_PUSHDATA2 = 0x4D;
    case OP_DUP       = 0x76;
    case OP_HASH160   = 0xA9;
    case OP_HASH256   = 0xAA;
}
