<?php

declare(strict_types=1);

namespace Bitcoin;

use Bitcoin\ECC\S256Point;
use Bitcoin\ECC\Signature;

final class ScriptInterpreter
{
    public static function evaluate(Script $script, \GMP $z): bool
    {
        $stack    = [];
        $altstack = [];
        $cmds     = $script->cmds;

        while (!empty($cmds)) {
            $cmd = array_pop($cmds);

            if (!\is_int($cmd)) {
                $stack[] = $cmd;
                continue;
            }

            if (!match ($cmd) {
                OpCodes::OP_IF->value    => self::opIf($stack, $cmds),
                OpCodes::OP_NOTIF->value => self::opNotIf($stack, $cmds),

                OpCodes::OP_TOALTSTACK->value   => self::opToAltStack($stack, $altstack),
                OpCodes::OP_FROMALTSTACK->value => self::opFromAltStack($stack, $altstack),

                OpCodes::OP_DUP->value     => self::opDup($stack),
                OpCodes::OP_HASH160->value => self::opHash160($stack),
                OpCodes::OP_HASH256->value => self::opHash256($stack),

                OpCodes::OP_CHECKSIG->value            => self::opCheckSig($stack, $z),
                OpCodes::OP_CHECKSIGVERIFY->value      => self::opCheckSig($stack, $z),
                OpCodes::OP_CHECKMULTISIG->value       => self::opCheckSig($stack, $z),
                OpCodes::OP_CHECKMULTISIGVERIFY->value => self::opCheckSig($stack, $z),

                default => false
            }) {
                return false;
            }
        }

        return !empty($stack) && "\x00" != $stack[array_key_last($stack)];
    }

    private static function opIf(array &$stack, array $cmds): bool
    {
        return false;
    }

    private static function opNotIf(array &$stack, array $cmds): bool
    {
        return false;
    }

    private static function opToAltStack(array &$stack, array &$altstack): bool
    {
        return false;
    }

    private static function opFromAltStack(array &$stack, array &$altstack): bool
    {
        return false;
    }

    private static function opDup(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = $stack[array_key_last($stack)];

        return true;
    }

    private static function opHash160(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $top     = array_pop($stack);
        $stack[] = Hashing::hash160($top);

        return true;
    }

    private static function opHash256(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $top     = array_pop($stack);
        $stack[] = Hashing::hash256($top);

        return true;
    }

    private static function opCheckSig(array &$stack, \GMP $z): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        try {
            $pubKey    = S256Point::parse(array_pop($stack));
            $signature = Signature::parse(array_pop($stack));
        } catch (\InvalidArgumentException) {
            return false;
        }

        $stack[] = $pubKey->verify($z, $signature) ? "\x01" : '';

        return true;
    }

    private static function opCheckSigVerify(array &$stack, \GMP $z): bool
    {
        return false;
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
