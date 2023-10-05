<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Tx\Script;

use Bitcoin\Tx\Script;
use Bitcoin\Tx\Script\Interpreter;
use Bitcoin\Tx\Script\OpCodes;
use PHPUnit\Framework\TestCase;

final class InterpreterTest extends TestCase
{
    public function testPayToPubKey(): void
    {
        // Based on example from Chapter 6 page 115
        $z = gmp_init('0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d');

        $sec = hex2bin('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34');
        $der = hex2bin('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601');

        $scriptPubKey = new Script([$sec, OpCodes::OP_CHECKSIG->value]);
        $scriptSig    = new Script([$der]);

        self::assertTrue(Interpreter::evaluate($scriptSig->combine($scriptPubKey), $z, witness: []));
    }

    public function testSillyScript(): void
    {
        // Based on example from Chapter 6 page 124
        $scriptPubKey = new Script([
            OpCodes::OP_5->value,
            OpCodes::OP_ADD->value,
            OpCodes::OP_9->value,
            OpCodes::OP_EQUAL->value,
        ]);

        $scriptSig = new Script([
            OpCodes::OP_4->value,
        ]);

        self::assertTrue(Interpreter::evaluate($scriptSig->combine($scriptPubKey), gmp_init(0), witness: []));
    }

    public function testSha1CollisionScript(): void
    {
        $scr = new Script(['a', 'b', 'c', OpCodes::OP_3DUP->value]);
        self::assertTrue(Interpreter::evaluate($scr, gmp_init(0), witness: []));

        // Based on exercise 4 from Chapter 6
        $scriptPubKey = new Script([    // 6E 87 91 69 A7 7C A7 87
            OpCodes::OP_2DUP->value,    // Duplicates the top two stack items.
            OpCodes::OP_EQUAL->value,   // Puts 1 on the stack if the inputs are exactly equal, 0 otherwise.
            OpCodes::OP_NOT->value,     // Replaces top element of the stack. If 0 -> 1, if 1 -> 0, otherwise 0.
            OpCodes::OP_VERIFY->value,  // Aborts execution as FALSE if top stack value is not true.
            OpCodes::OP_SHA1->value,    // Replaces top element of the stack with its SHA1 hash.
            OpCodes::OP_SWAP->value,    // Swaps top two elements of the stack
            OpCodes::OP_SHA1->value,    // Replaces top element of the stack with its SHA1 hash.
            OpCodes::OP_EQUAL->value,   // Puts 1 on the stack if the inputs are exactly equal, 0 otherwise.
        ]);

        // Known SHA-1 collision
        $scriptSig = new Script([
            hex2bin('255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017f46dc93a6b67e013b029aaa1db2560b45ca67d688c7f84b8c4c791fe02b3df614f86db1690901c56b45c1530afedfb76038e972722fe7ad728f0e4904e046c230570fe9d41398abe12ef5bc942be33542a4802d98b5d70f2a332ec37fac3514e74ddc0f2cc1a874cd0c78305a21566461309789606bd0bf3f98cda8044629a1'),
            hex2bin('255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474682032203020522f4865696768742033203020522f547970652034203020522f537562747970652035203020522f46696c7465722036203020522f436f6c6f7253706163652037203020522f4c656e6774682038203020522f42697473506572436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d3120697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe017346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de218f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d23c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1'),
        ]);

        self::assertTrue(Interpreter::evaluate($scriptSig->combine($scriptPubKey), gmp_init(0), witness: []));

        // Initial state (ScriptSig)
        // A
        // B

        // OP_2DUP
        // A
        // B
        // A
        // B

        // OP_EQUAL
        // 0
        // A
        // B

        // OP_NOT
        // 1
        // A
        // B

        // OP_VERIFY - At this point we've checked that A and B are not the same value
        //             while retaining them in the stack.
        // A
        // B

        // OP_SHA1
        // SHA1(A)
        // B

        // OP_SWAP
        // B
        // SHA1(A)

        // OP_SHA1
        // SHA1(B)
        // SHA1(A)

        // OP_EQUAL (1 if A and B sha1 to the same hash, 0 otherwise)
        // 1
    }
}
