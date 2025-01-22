<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script;

use Bitcoin\Encoding;
use Bitcoin\Tx\Script;

final readonly class Interpreter
{
    public static function evaluate(Script $script, \GMP $z, array $witness): bool
    {
        $stack    = [];
        $altstack = [];
        $cmds     = $script->cmds;

        while (!empty($cmds)) {
            $cmd = array_shift($cmds);

            if (!\is_int($cmd)) {
                $stack[] = $cmd;

                if (self::payToScriptHashSequence($cmds)) {
                    if (!self::payToScriptHashEvaluation($cmds, $stack, $cmd)) {
                        return false;
                    }
                }

                if (self::payToWitnessPubKeyHashSequence($stack)) {
                    $cmds = array_merge($cmds, $witness);
                    $cmds = array_merge($cmds, Script::payToPubKeyHash(array_pop($stack))->cmds);

                    array_pop($stack); // OP_0
                }

                if (self::payToWitnessScriptHashSequence($stack)) {
                    $witnessScript = $witness[array_key_last($witness)];
                    if (array_pop($stack) !== hash('sha256', $witnessScript, true)) {
                        return false;
                    }

                    $cmds = array_merge($cmds, \array_slice($witness, 0, -1));
                    $cmds = array_merge($cmds, Script::parseAsString(Encoding::encodeVarInt(\strlen($witnessScript)).$witnessScript)->cmds);

                    array_pop($stack); // OP_O
                }

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
                OpCodes::OP_2DROP->value               => OpCodes\OpDrop::eval($stack),
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

                default => false,
            }) {
                return false;
            }
        }

        return OpCodes\OpVerify::eval($stack);
    }

    /**
     * BIP-16 special handling for P2SH. Detects the OP_HASH160 <20 byte> OP_EQUAL sequence in the command list.
     *
     * @see https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
     */
    private static function payToScriptHashSequence(array $cmds): bool
    {
        return 3        === \count($cmds)
            && $cmds[0] === OpCodes::OP_HASH160->value
            && \is_string($cmds[1])
            && 20       === \strlen($cmds[1])
            && $cmds[2] === OpCodes::OP_EQUAL->value;
    }

    private static function payToScriptHashEvaluation(array &$cmds, array &$stack, string $script): bool
    {
        array_shift($cmds);
        $scriptHash = array_shift($cmds);
        array_shift($cmds);

        // Stack is empty so no element can be hashed
        if (!OpCodes\OpHash::eval($stack, 'hash160')) {
            return false;
        }

        $stack[] = $scriptHash;

        // The two topmost elements of the stack aren't equal
        if (!(OpCodes\OpEqual::eval($stack) && OpCodes\OpVerify::eval($stack))) {
            return false;
        }

        // Parse RedeemScript (it's still $cmd from before we entered the BIP-16 branch)
        // and assign it to the command list (it's empty at this point).
        try {
            $cmds = Script::parseAsString(Encoding::encodeVarInt(\strlen($script)).$script)->cmds;
        } catch (\InvalidArgumentException) {
            // Invalid script that cannot be correctly parsed.
            return false;
        }

        return true;
    }

    private static function payToWitnessPubKeyHashSequence(array $stack): bool
    {
        return 2         === \count($stack)
            && $stack[0] === Encoding::encodeStackNum(0)
            && \is_string($stack[1])
            && 20 === \strlen($stack[1]);
    }

    private static function payToWitnessScriptHashSequence(array $stack): bool
    {
        return 2         === \count($stack)
            && $stack[0] === Encoding::encodeStackNum(0)
            && \is_string($stack[1])
            && 32 === \strlen($stack[1]);
    }
}
