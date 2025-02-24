<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Network;

use Bitcoin\Network;
use Bitcoin\Network\Envelope;
use Bitcoin\Network\Message;
use Bitcoin\Tests\StreamingHelperTrait;
use PHPUnit\Framework\TestCase;

final class EnvelopeTest extends TestCase
{
    use StreamingHelperTrait;

    private const string SAMPLE_VERACK_NETWORK_ENVELOPE = 'f9beb4d976657261636b000000000000000000005df6e0e2';

    public function testParsing(): void
    {
        $envelope = Envelope::parse(self::stream(hex2bin(self::SAMPLE_VERACK_NETWORK_ENVELOPE)), Network::MAINNET);

        self::assertSame(Network::MAINNET, $envelope->network);
        self::assertSame('verack', $envelope->command);
        self::assertSame('', $envelope->payload);

        self::assertSame(self::SAMPLE_VERACK_NETWORK_ENVELOPE, bin2hex($envelope->serialize()));
    }

    public function testTalkToMe(): void
    {
        $socket = fsockopen('127.0.0.1', 18444);

        if (false === $socket) {
            self::markTestSkipped('regtest node is unavailable');
        }

        $version = new Message\Version(
            70016,
            0,
            (int) new \DateTimeImmutable()->format('U'),
            0,
            '',
            0,
            0,
            '',
            0,
            1234,
            '/Programming Bitcoin in PHP/',
            0,
            false
        );

        fwrite($socket, Envelope::build($version, Network::REGTEST)->serialize());

        $response = Envelope::parse($socket, Network::REGTEST);
        fclose($socket);

        self::assertSame('version', $response->command);
        self::assertStringContainsString('Knots', $response->payload);
    }
}
