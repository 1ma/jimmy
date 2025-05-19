<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Encoding;

use Bitcoin\Encoding\Bech32;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Bech32Test extends TestCase
{
    private const string TEST_VECTOR_EXTRACTOR = __DIR__.'/../bech32_sipatronic_testcase_extractor.py';

    #[DataProvider('validAddressProvider')]
    public function testValidAddress(string $address, string $program): void
    {
        [$version, $decodedProgram] = Bech32::segwitDecode($address, strtolower(substr($address, 0, 2)));

        self::assertSame(hex2bin($program), self::segwitScriptPubKey($version, $decodedProgram));

        self::assertSame(strtolower($address), Bech32::segwitEncode($version, $decodedProgram, strtolower(substr($address, 0, 2))));
    }

    public static function validAddressProvider(): array
    {
        return self::extractTestVectors()->VALID_ADDRESS;
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

    #[DataProvider('invalidAddressProvider')]
    public function testInvalidAddress(string $invalidAddress): void
    {
        $exceptions = 0;

        try {
            Bech32::segwitDecode($invalidAddress, Bech32::TESTNET_HRP);
        } catch (\InvalidArgumentException) {
            ++$exceptions;
        }

        try {
            Bech32::segwitDecode($invalidAddress, Bech32::MAINNET_HRP);
        } catch (\InvalidArgumentException) {
            ++$exceptions;
        }

        self::assertSame(2, $exceptions);
    }

    public static function invalidAddressProvider(): array
    {
        return array_map(
            static fn (string $v): array => [$v],
            self::extractTestVectors()->INVALID_ADDRESS
        );
    }

    #[DataProvider('validBech32Provider')]
    public function testValidBech32Strings(string $data): void
    {
        [$hrp, $decoded, $spec] = Bech32::decode($data);

        self::assertSame(strtolower($data), Bech32::encode($decoded, $hrp, $spec));
    }

    public static function validBech32Provider(): array
    {
        $allTests = self::extractTestVectors();

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
        $allTests = self::extractTestVectors();

        return array_map(
            static fn (string $v): array => [$v],
            array_merge($allTests->INVALID_BECH32, $allTests->INVALID_BECH32M)
        );
    }

    public function testCharacterOutOfRange(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Bech32::segwitEncode(0, [256], Bech32::MAINNET_HRP);
    }

    #[DataProvider('invalidAddressEncodingProvider')]
    public function testInvalidAddressEncoding(string $hrp, int $version, int $length): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Bech32::segwitEncode($version, array_fill(0, $length, 0), $hrp);
    }

    public static function invalidAddressEncodingProvider(): array
    {
        return self::extractTestVectors()->INVALID_ADDRESS_ENC;
    }

    private static function extractTestVectors(): \stdClass
    {
        return json_decode(shell_exec('python3 '.self::TEST_VECTOR_EXTRACTOR));
    }
}
