<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Encoding;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Bech32Test extends TestCase
{
    private const string TEST_VECTOR_EXTRACTOR = 'python3 '.__DIR__.'/../bech32_sipatronic_extractor.py';

    #[DataProvider('validAddressProvider')]
    public function testValidAddress(string $address, string $data): void
    {
        self::assertIsString($address);
        self::assertIsString($data);
    }

    public static function validAddressProvider(): array
    {
        return json_decode(shell_exec(self::TEST_VECTOR_EXTRACTOR), true)['VALID_ADDRESS'];
    }
}
