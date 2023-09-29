<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script;

use Bitcoin\ECC\S256Point;
use Bitcoin\ECC\Signature;
use Bitcoin\Hashing;
use Bitcoin\Tx\Script;

final class Interpreter
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

            if (OpCodes::OP_1->value <= $cmd && $cmd <= OpCodes::OP_16->value) {
                self::opNum($stack, $cmd - OpCodes::OP_1->value + 1);
                continue;
            }

            if (!match ($cmd) {
                OpCodes::OP_0->value => self::opNum($stack, 0),

                OpCodes::OP_IF->value    => self::opIf($stack, $cmds),
                OpCodes::OP_NOTIF->value => self::opNotIf($stack, $cmds),

                OpCodes::OP_VERIFY->value => self::opVerify($stack),

                OpCodes::OP_TOALTSTACK->value   => self::opToAltStack($stack, $altstack),
                OpCodes::OP_FROMALTSTACK->value => self::opFromAltStack($stack, $altstack),

                OpCodes::OP_2DUP->value => self::op2Dup($stack),

                OpCodes::OP_DUP->value  => self::opDup($stack),
                OpCodes::OP_SWAP->value => self::opSwap($stack),

                OpCodes::OP_EQUAL->value       => self::opEqual($stack),
                OpCodes::OP_EQUALVERIFY->value => self::opEqualVerify($stack),

                OpCodes::OP_NOT->value => self::opNot($stack),
                OpCodes::OP_ADD->value => self::opAdd($stack),

                OpCodes::OP_RIPEMD160->value => self::opHash($stack, 'ripemd160'),
                OpCodes::OP_SHA1->value      => self::opHash($stack, 'sha1'),
                OpCodes::OP_SHA256->value    => self::opHash($stack, 'sha256'),
                OpCodes::OP_HASH160->value   => self::opHash160($stack),
                OpCodes::OP_HASH256->value   => self::opHash256($stack),

                OpCodes::OP_CHECKSIG->value            => self::opCheckSig($stack, $z),
                OpCodes::OP_CHECKSIGVERIFY->value      => self::opCheckSigVerify($stack, $z),
                OpCodes::OP_CHECKMULTISIG->value       => self::opCheckMultiSig($stack, $z),
                OpCodes::OP_CHECKMULTISIGVERIFY->value => self::opCheckMultiSigVerify($stack, $z),

                default => false
            }) {
                return false;
            }
        }

        return !empty($stack) && self::encodeNum(0) !== $stack[array_key_last($stack)];
    }

    private static function encodeNum(int $num): string
    {
        if (0 === $num) {
            return '';
        }

        $absNum   = abs($num);
        $negative = $num < 0;
        $result   = [];
        while ($absNum > 0) {
            $result[] = $absNum & 0xFF;
            $absNum >>= 8;
        }

        if ($result[array_key_last($result)] & 0x80) {
            $result[] = $negative ? 0x80 : 0x00;
        } elseif ($negative) {
            $result[array_key_last($result)] |= 0x80;
        }

        return pack('C'.\count($result), ...$result);
    }

    private static function decodeNum(string $element): int
    {
        if ('' === $element) {
            return 0;
        }

        $bigEndian = array_values(unpack('C'.\strlen($element), strrev($element)));

        $negative = $bigEndian[0] & 0x80;
        $result   = $bigEndian[0] & 0x80 ? $bigEndian[0] & 0x7F : $bigEndian[0];

        for ($i = 1; $i < \count($bigEndian); ++$i) {
            $result <<= 8;
            $result += $bigEndian[$i];
        }

        return $negative ? -$result : $result;
    }

    private static function opNum(array &$stack, int $num): bool
    {
        $stack[] = self::encodeNum($num);

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
        return !empty($stack) && self::encodeNum(0) !== array_pop($stack);
    }

    private static function opToAltStack(array &$stack, array &$altstack): bool
    {
        return false;
    }

    private static function opFromAltStack(array &$stack, array &$altstack): bool
    {
        return false;
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
            self::encodeNum(1) :
            self::encodeNum(0);

        return true;
    }

    private static function opEqualVerify(array &$stack): bool
    {
        return self::opEqual($stack) && self::opVerify($stack);
    }

    private static function OpNot(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = match (self::decodeNum(array_pop($stack))) {
            0       => self::encodeNum(1),
            default => self::encodeNum(0)
        };

        return true;
    }

    private static function opAdd(array &$stack): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        $stack[] = self::encodeNum(
            self::decodeNum(array_pop($stack)) + self::decodeNum(array_pop($stack))
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
            self::encodeNum(1) :
            self::encodeNum(0);

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
