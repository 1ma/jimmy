<?php

declare(strict_types=1);

namespace Bitcoin\Tests\BIP39;

use Bitcoin\BIP39\Mnemonic;
use PHPUnit\Framework\TestCase;

final class SeedTest extends TestCase
{
    private const string REFERENCE_WORDLIST_PATH = __DIR__.'/../../vendor/trezor/bip39/src/mnemonic/wordlist/english.txt';

    public function testWordlistIsCorrect(): void
    {
        self::assertCount(2048, Mnemonic::WORDLIST);

        $referenceList = file(self::REFERENCE_WORDLIST_PATH, \FILE_IGNORE_NEW_LINES);

        foreach ($referenceList as $index => $word) {
            self::assertSame($word, Mnemonic::WORDLIST[$index]);
        }
    }
}
