<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script;

use Bitcoin\Tx\Script;

final readonly class Interpreter
{
    public static function evaluate(Script $script, \GMP $z): bool
    {
        $stack    = [];
        $altstack = [];
        $cmds     = $script->cmds;

        while (!empty($cmds)) {
            $cmd = array_shift($cmds);

            if (!\is_int($cmd)) {
                $stack[] = $cmd;
                continue;
            }

            // So that's why they called it OP_RETURN. Bonkers.
            if (OpCodes::OP_RETURN->value === $cmd) {
                return false;
            }

            if (OpCodes::OP_1->value <= $cmd && $cmd <= OpCodes::OP_16->value) {
                OpCodes\OpNum::eval($stack, $cmd - OpCodes::OP_1->value + 1);
                continue;
            }

            if (!match ($cmd) {
                OpCodes::OP_0->value                   => OpCodes\OpNum::eval($stack, 0),
                OpCodes::OP_VERIFY->value              => OpCodes\OpVerify::eval($stack),
                OpCodes::OP_TOALTSTACK->value          => OpCodes\OpAltStack::eval($stack, $altstack),
                OpCodes::OP_FROMALTSTACK->value        => OpCodes\OpAltStack::eval($altstack, $stack),
                OpCodes::OP_DROP->value                => OpCodes\OpDrop::eval($stack),
                OpCodes::OP_2DUP->value                => OpCodes\Op2Dup::eval($stack),
                OpCodes::OP_3DUP->value                => OpCodes\Op3Dup::eval($stack),
                OpCodes::OP_DUP->value                 => OpCodes\OpDup::eval($stack),
                OpCodes::OP_SWAP->value                => OpCodes\OpSwap::eval($stack),
                OpCodes::OP_EQUAL->value               => OpCodes\OpEqual::eval($stack),
                OpCodes::OP_EQUALVERIFY->value         => OpCodes\OpEqual::eval($stack) && OpCodes\OpVerify::eval($stack),
                OpCodes::OP_NOT->value                 => OpCodes\OpNot::eval($stack, 1, 0),
                OpCodes::OP_0NOTEQUAL->value           => OpCodes\OpNot::eval($stack, 0, 1),
                OpCodes::OP_ADD->value                 => OpCodes\OpAdd::eval($stack),
                OpCodes::OP_RIPEMD160->value           => OpCodes\OpHash::eval($stack, 'ripemd160'),
                OpCodes::OP_SHA1->value                => OpCodes\OpHash::eval($stack, 'sha1'),
                OpCodes::OP_SHA256->value              => OpCodes\OpHash::eval($stack, 'sha256'),
                OpCodes::OP_HASH160->value             => OpCodes\OpHash::eval($stack, 'hash160'),
                OpCodes::OP_HASH256->value             => OpCodes\OpHash::eval($stack, 'hash256'),
                OpCodes::OP_CHECKSIG->value            => OpCodes\OpCheckSig::eval($stack, $z),
                OpCodes::OP_CHECKSIGVERIFY->value      => OpCodes\OpCheckSig::eval($stack, $z) && OpCodes\OpVerify::eval($stack),
                OpCodes::OP_CHECKMULTISIG->value       => OpCodes\OpCheckMultiSig::eval($stack, $z),
                OpCodes::OP_CHECKMULTISIGVERIFY->value => OpCodes\OpCheckMultiSig::eval($stack, $z) && OpCodes\OpVerify::eval($stack),

                default => false
            }) {
                return false;
            }
        }

        return OpCodes\OpVerify::eval($stack);
    }
}
