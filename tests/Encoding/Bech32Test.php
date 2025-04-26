<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Encoding;

use Bitcoin\Encoding\Bech32;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Bech32Test extends TestCase
{
    private const string TEST_VECTOR_EXTRACTOR = 'python3 '.__DIR__.'/../bech32_sipatronic_extractor.py';

    public function testConvertBits(): void
    {
        self::assertSame([0, 0], Bech32::convertBits([0], 8, 5, true));
        self::assertSame([0, 4], Bech32::convertBits([1], 8, 5, true));
        self::assertSame([0, 4, 0, 16], Bech32::convertBits([1, 1], 8, 5, true));
    }

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

    #[DataProvider('validBech32Provider')]
    public function testValidBech32Strings(string $data): void
    {
        [$hrp, $decoded, $spec] = Bech32::decode($data);

        self::assertSame(strtolower($data), Bech32::encode($decoded, $hrp, $spec));
    }

    public static function validBech32Provider(): array
    {
        $allTests = json_decode(shell_exec(self::TEST_VECTOR_EXTRACTOR));

        return array_map(
            static fn (string $v): array => [$v],
            array_merge($allTests->VALID_BECH32, $allTests->VALID_BECH32M)
        );
    }

    #[DataProvider('invalidBech32Provider')]
    public function testInvalidBech32Strings(string $data): void
    {
        self::expectException(\InvalidArgumentException::class);

        Bech32::decode($data);
    }

    public static function invalidBech32Provider(): array
    {
        $allTests = json_decode(shell_exec(self::TEST_VECTOR_EXTRACTOR));

        return array_map(
            static fn (string $v): array => [$v],
            array_merge($allTests->INVALID_BECH32, $allTests->INVALID_BECH32M)
        );
    }
}
