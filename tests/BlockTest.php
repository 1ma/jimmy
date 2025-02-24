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

    private const string BLOCK_471744_HEADER = '000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd8800000000000000000010c8aba8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448ddb845597e8b0118e43a81d3';
    private const string BLOCK_473759_HEADER = '02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc26000000000000000000b3f449fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc144973735eea707e1264258597e8b0118e5f00474';
    private const string BLOCK_473760_HEADER = '0200002099d6a70c547bbaa1a820490bd02cc378d3bc6e20469438010000000000000000b66a0b024cfdf07d0dd97e18ad6ef1a411b0452129d3bfe3e6ebae55defec4dd95425859308d0118bc260a08';

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

    public function testNewTargetCalculation(): void
    {
        $firstBlock = Block::parse(self::stream(hex2bin(self::BLOCK_471744_HEADER)));
        $lastBlock  = Block::parse(self::stream(hex2bin(self::BLOCK_473759_HEADER)));
        $nextBlock  = Block::parse(self::stream(hex2bin(self::BLOCK_473760_HEADER)));

        $nextTarget = Block::newTarget($firstBlock, $lastBlock);
        $nextBits   = Block::targetToBits($nextTarget);

        self::assertSame($nextBlock->bits, $nextBits);
    }
}
