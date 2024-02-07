<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Network;

use Bitcoin\Network\Envelope;
use Bitcoin\Tests\StreamingHelperTrait;
use PHPUnit\Framework\TestCase;

final class EnvelopeTest extends TestCase
{
    use StreamingHelperTrait;

    private const string SAMPLE_VERACK_NETWORK_ENVELOPE = 'f9beb4d976657261636b000000000000000000005df6e0e2';

    public function testParsing(): void
    {
        $envelope = Envelope::parse(self::stream(hex2bin(self::SAMPLE_VERACK_NETWORK_ENVELOPE)), testnet: false);

        self::assertSame(Envelope::MAINNET_MAGIC, $envelope->magic);
        self::assertSame('verack', $envelope->command);
        self::assertSame('', $envelope->payload);

        self::assertSame(self::SAMPLE_VERACK_NETWORK_ENVELOPE, bin2hex($envelope->serialize()));
    }
}
