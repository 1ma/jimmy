<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\Hashing;
use PHPUnit\Framework\TestCase;

final class HashingTest extends TestCase
{
    public function testMerkleParent(): void
    {
        // Based on example from Chapter 11 page 191
        $child0 = hex2bin('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5');
        $child1 = hex2bin('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5');
        $parent = hex2bin('8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd');

        self::assertSame($parent, Hashing::merkleParent($child0, $child1));
    }

    public function testMerkleParentLevel(): void
    {
        // Based on example from Chapter 11 page 192
        $children = [
            hex2bin('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5'),
            hex2bin('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5'),
            hex2bin('f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0'),
            hex2bin('3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181'),
            hex2bin('10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae'),
        ];

        $parents = [
            hex2bin('8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd'),
            hex2bin('7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800'),
            hex2bin('3ecf6115380c77e8aae56660f5634982ee897351ba906a6837d15ebc3a225df0'),
        ];

        self::assertSame($parents, Hashing::merkleParentLevel($children));
    }

    public function testMerkleRoot(): void
    {
        // Based on example from Chapter 11 page 193
        $leaves = [
            hex2bin('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5'),
            hex2bin('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5'),
            hex2bin('f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0'),
            hex2bin('3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181'),
            hex2bin('10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae'),
            hex2bin('7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161'),
            hex2bin('8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc'),
            hex2bin('dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877'),
            hex2bin('b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59'),
            hex2bin('95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c'),
            hex2bin('2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908'),
            hex2bin('b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0'),
        ];

        $root = hex2bin('acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed6');

        self::assertSame($root, Hashing::merkleRoot($leaves));
    }
}
