<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\OpCodes;
use Bitcoin\Script;
use Bitcoin\ScriptInterpreter;
use PHPUnit\Framework\TestCase;

final class ScriptInterpreterTest extends TestCase
{
    public function testPayToPubKey(): void
    {
        // Based on example from Chapter 6 page 115
        $z = gmp_init('0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d');

        $sec = hex2bin('04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34');
        $der = hex2bin('3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab601');

        $scriptPubKey = new Script([$sec, OpCodes::OP_CHECKSIG->value]);
        $scriptSig    = new Script([$der]);

        self::assertTrue(ScriptInterpreter::evaluate($scriptSig->combine($scriptPubKey), $z));
    }
}
