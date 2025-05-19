<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\Hashing;
use PHPUnit\Framework\TestCase;

final class HashingTest extends TestCase
{
    public function testMerkleParent(): void
    {
        $hash0  = hex2bin('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5');
        $hash1  = hex2bin('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5');
        $parent = hex2bin('8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd');

        self::assertSame($parent, Hashing::merkleParent($hash0, $hash1));
    }
}
