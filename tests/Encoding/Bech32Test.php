<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Encoding;

use Bitcoin\Encoding\Bech32;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Bech32Test extends TestCase
{
    private const string TEST_VECTOR_EXTRACTOR = 'python3 '.__DIR__.'/../bech32_sipatronic_extractor.py';

    #[DataProvider('validAddressProvider')]
    public function testValidAddress(string $address, string $program): void
    {
        [$version, $decodedProgram] = Bech32::segwitDecode($address, strtolower(substr($address, 0, 2)));

        self::assertSame(hex2bin($program), self::segwitScriptPubKey($version, $decodedProgram));
    }

    public static function validAddressProvider(): array
    {
        return json_decode(shell_exec(self::TEST_VECTOR_EXTRACTOR))->VALID_ADDRESS;
    }

    public function testConvertBits(): void
    {
        self::assertSame([0, 0], Bech32::convertBits([0], 8, 5, true));
        self::assertSame([0, 4], Bech32::convertBits([1], 8, 5, true));
        self::assertSame([0, 4, 0, 16], Bech32::convertBits([1, 1], 8, 5, true));
    }

    /**
     * @param int[] $program
     */
    private function segwitScriptPubKey(int $version, array $program): string
    {
        if (0 !== $version) {
            $version += 0x50;
        }

        return pack('C*', ...array_merge([$version, \count($program)], $program));
    }
}
