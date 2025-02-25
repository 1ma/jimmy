<?php

declare(strict_types=1);

namespace Network;

use Bitcoin\Network;
use Bitcoin\Network\Message;
use PHPUnit\Framework\TestCase;

final class SimpleNodeTest extends TestCase
{
    public function testNetworkHandshake(): void
    {
        try {
            $node = new Network\SimpleNode('127.0.0.1', 18444, false, Network::REGTEST);
        } catch (\RuntimeException) {
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

        $node->send($version);

        $versionReceived = false;
        $verackReceived  = false;

        while (!($versionReceived && $verackReceived)) {
            $response = $node->recv();

            if ('version' === $response->command) {
                $versionReceived = true;
                self::assertStringContainsString('Knots', $response->payload);
                $node->send(new Message\VerAck());
            } elseif ('verack' === $response->command) {
                $verackReceived = true;
                self::assertSame('', $response->payload);
            }
        }

        $node->close();
    }

    public function testSimpleNodeHandshake(): void
    {
        try {
            $node = new Network\SimpleNode('127.0.0.1', 18444, false, Network::REGTEST);
        } catch (\RuntimeException) {
            self::markTestSkipped('regtest node is unavailable');
        }

        $node->handshake();

        while ($response = $node->recv()) {
            if ('ping' === $response->command) {
                self::assertNotEmpty($response->payload);
                break;
            }
        }

        $node->close();
    }
}
