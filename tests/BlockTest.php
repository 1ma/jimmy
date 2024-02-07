<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\Block;
use Bitcoin\Encoding;
use Bitcoin\Hashing;
use PHPUnit\Framework\TestCase;

final class BlockTest extends TestCase
{
    use StreamingHelperTrait;

    private const string BLOCK_HEADER = '020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d';

    public function testBlockMethods(): void
    {
        $block = Block::parse(self::stream(hex2bin(self::BLOCK_HEADER)));

        self::assertSame(0x20000002, $block->version);
        self::assertSame('000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e', $block->prevBlock);
        self::assertSame('be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b', $block->merkleRoot);
        self::assertSame(1504147230, $block->timestamp);
        self::assertSame(0x18013CE9, $block->bits);
        self::assertSame(0x1DD7FFA4, $block->nonce);

        self::assertSame(hex2bin(self::BLOCK_HEADER), $block->serialize());

        self::assertSame('0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523', $block->id());

        self::assertSame('13ce9000000000000000000000000000000000000000000', gmp_strval($block->target(), 16));
        self::assertSame('888171856257', gmp_strval($block->difficulty()));

        self::assertTrue($block->bip9());
        self::assertFalse($block->bip91());
        self::assertTrue($block->bip141());
    }

    public function testValidBlockProofOfWork(): void
    {
        $block = Block::parse(self::stream(hex2bin(self::BLOCK_HEADER)));
        $proof = Encoding::fromLE(Hashing::hash256(hex2bin(self::BLOCK_HEADER)));

        self::assertTrue($proof < $block->target());

        $paddedProof = str_pad(gmp_strval($proof, 16), 64, '0', \STR_PAD_LEFT);

        self::assertSame($paddedProof, $block->id());

        self::assertTrue($block->checkPOW());
    }
}
