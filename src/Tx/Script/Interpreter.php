<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script;

use Bitcoin\ECC\S256Point;
use Bitcoin\ECC\Signature;
use Bitcoin\Encoding;
use Bitcoin\Hashing;
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
                self::opNum($stack, $cmd - OpCodes::OP_1->value + 1);
                continue;
            }

            if (!match ($cmd) {
                OpCodes::OP_0->value                   => self::opNum($stack, 0),
                OpCodes::OP_IF->value                  => self::opIf($stack, $cmds),
                OpCodes::OP_NOTIF->value               => self::opNotIf($stack, $cmds),
                OpCodes::OP_VERIFY->value              => self::opVerify($stack),
                OpCodes::OP_TOALTSTACK->value          => self::opToAltStack($stack, $altstack),
                OpCodes::OP_FROMALTSTACK->value        => self::opFromAltStack($stack, $altstack),
                OpCodes::OP_DROP->value                => self::opDrop($stack),
                OpCodes::OP_2DUP->value                => self::op2Dup($stack),
                OpCodes::OP_3DUP->value                => self::op3Dup($stack),
                OpCodes::OP_DUP->value                 => self::opDup($stack),
                OpCodes::OP_SWAP->value                => self::opSwap($stack),
                OpCodes::OP_EQUAL->value               => self::opEqual($stack),
                OpCodes::OP_EQUALVERIFY->value         => self::opEqualVerify($stack),
                OpCodes::OP_NOT->value                 => self::opNot($stack),
                OpCodes::OP_0NOTEQUAL->value           => self::op0NotEqual($stack),
                OpCodes::OP_ADD->value                 => self::opAdd($stack),
                OpCodes::OP_RIPEMD160->value           => self::opHash($stack, 'ripemd160'),
                OpCodes::OP_SHA1->value                => self::opHash($stack, 'sha1'),
                OpCodes::OP_SHA256->value              => self::opHash($stack, 'sha256'),
                OpCodes::OP_HASH160->value             => self::opHash160($stack),
                OpCodes::OP_HASH256->value             => self::opHash256($stack),
                OpCodes::OP_CHECKSIG->value            => self::opCheckSig($stack, $z),
                OpCodes::OP_CHECKSIGVERIFY->value      => self::opCheckSigVerify($stack, $z),
                OpCodes::OP_CHECKMULTISIG->value       => self::opCheckMultiSig($stack, $z),
                OpCodes::OP_CHECKMULTISIGVERIFY->value => self::opCheckMultiSigVerify($stack, $z),

                default => false
            }) {
                return false;
            }
        }

        return !empty($stack) && Encoding::encodeStackNum(0) !== $stack[array_key_last($stack)];
    }

    private static function opNum(array &$stack, int $num): bool
    {
        $stack[] = Encoding::encodeStackNum($num);

        return true;
    }

    private static function opIf(array &$stack, array $cmds): bool
    {
        return false;
    }

    private static function opNotIf(array &$stack, array $cmds): bool
    {
        return false;
    }

    private static function opVerify(array &$stack): bool
    {
        return !empty($stack) && Encoding::encodeStackNum(0) !== array_pop($stack);
    }

    private static function opToAltStack(array &$stack, array &$altstack): bool
    {
        return false;
    }

    private static function opFromAltStack(array &$stack, array &$altstack): bool
    {
        return false;
    }

    private static function opDrop(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        array_pop($stack);

        return true;
    }

    private static function op2Dup(array &$stack): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        $stack[] = $stack[array_key_last($stack) - 1];
        $stack[] = $stack[array_key_last($stack) - 1];

        return true;
    }

    private static function op3Dup(array &$stack): bool
    {
        if (\count($stack) < 3) {
            return false;
        }

        $stack[] = $stack[array_key_last($stack) - 2];
        $stack[] = $stack[array_key_last($stack) - 2];
        $stack[] = $stack[array_key_last($stack) - 2];

        return true;
    }

    private static function opDup(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = $stack[array_key_last($stack)];

        return true;
    }

    private static function opSwap(array &$stack): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        $a = array_pop($stack);
        $b = array_pop($stack);

        $stack[] = $a;
        $stack[] = $b;

        return true;
    }

    private static function opEqual(array &$stack): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        $stack[] = array_pop($stack) === array_pop($stack) ?
            Encoding::encodeStackNum(1) :
            Encoding::encodeStackNum(0);

        return true;
    }

    private static function opEqualVerify(array &$stack): bool
    {
        return self::opEqual($stack) && self::opVerify($stack);
    }

    private static function opNot(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = match (Encoding::decodeStackNum(array_pop($stack))) {
            0       => Encoding::encodeStackNum(1),
            default => Encoding::encodeStackNum(0)
        };

        return true;
    }

    private static function op0NotEqual(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = match (Encoding::decodeStackNum(array_pop($stack))) {
            0       => Encoding::encodeStackNum(0),
            default => Encoding::encodeStackNum(1)
        };

        return true;
    }

    private static function opAdd(array &$stack): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        $stack[] = Encoding::encodeStackNum(
            Encoding::decodeStackNum(array_pop($stack)) + Encoding::decodeStackNum(array_pop($stack))
        );

        return true;
    }

    private static function opHash(array &$stack, string $algorithm): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = hash($algorithm, array_pop($stack), true);

        return true;
    }

    private static function opHash160(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = Hashing::hash160(array_pop($stack));

        return true;
    }

    private static function opHash256(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = Hashing::hash256(array_pop($stack));

        return true;
    }

    private static function opCheckSig(array &$stack, \GMP $z): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        try {
            $pubKey = S256Point::parse(array_pop($stack));

            // sighash byte must be stripped from the DER data
            $signature = Signature::parse(substr(array_pop($stack), 0, -1));
        } catch (\InvalidArgumentException) {
            return false;
        }

        $stack[] = $pubKey->verify($z, $signature) ?
            Encoding::encodeStackNum(1) :
            Encoding::encodeStackNum(0);

        return true;
    }

    private static function opCheckSigVerify(array &$stack, \GMP $z): bool
    {
        return self::opCheckSig($stack, $z) && self::opVerify($stack);
    }

    private static function opCheckMultiSig(array &$stack, \GMP $z): bool
    {
        return false;
    }

    private static function opCheckMultiSigVerify(array &$stack, \GMP $z): bool
    {
        return false;
    }
}
