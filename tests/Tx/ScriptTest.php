<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Tx;

use Bitcoin\Tx\Script;
use PHPUnit\Framework\TestCase;

final class ScriptTest extends TestCase
{
    public function testSerializationOfEmptyScript(): void
    {
        self::assertSame("\x00", (new Script())->serialize());
    }
}
