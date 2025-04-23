<?php

declare(strict_types=1);

namespace Bitcoin\Tests\HDW;

use Bitcoin\HDW\ExtendedKey;
use Bitcoin\HDW\Mnemonic;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MnemonicTest extends TestCase
{
    private const string TEST_VECTORS_PATH       = __DIR__.'/../../vendor/trezor/bip39/vectors.json';
    private const string REFERENCE_WORDLIST_PATH = __DIR__.'/../../vendor/trezor/bip39/src/mnemonic/wordlist/english.txt';

    public function testWordlistIsCorrect(): void
    {
        self::assertCount(2048, Mnemonic::WORDLIST);

        $referenceList = file(self::REFERENCE_WORDLIST_PATH, \FILE_IGNORE_NEW_LINES);

        foreach ($referenceList as $index => $word) {
            self::assertSame($word, Mnemonic::WORDLIST[$index]);
        }
    }

    #[DataProvider('trezorEnglishVectorsProvider')]
    public function testTrezorVectors(string $entropy, string $words, string $seed, string $xprv): void
    {
        self::assertSame(hex2bin($seed), Mnemonic::decode(explode(' ', $words), 'TREZOR'));
        self::assertSame($xprv, ExtendedKey::create(hex2bin($seed), mainnet: true)->serialize());
    }

    public static function trezorEnglishVectorsProvider(): array
    {
        return json_decode(file_get_contents(self::TEST_VECTORS_PATH))->english;
    }
}
