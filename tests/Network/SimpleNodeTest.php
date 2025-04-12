<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Network;

use Bitcoin\Block;
use Bitcoin\Network;
use Bitcoin\Network\Message;
use Bitcoin\Tests\StreamingHelperTrait;
use PHPUnit\Framework\TestCase;

final class SimpleNodeTest extends TestCase
{
    use StreamingHelperTrait;

    private const string REGTEST_GENESIS_BLOCK = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000';
    private const string REGTEST_GENESIS_ID    = '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206';
    private const string ZERO_HASH_BLOCK       = '0000000000000000000000000000000000000000000000000000000000000000';

    public function testNetworkHandshake(): void
    {
        $node = self::startNode();

        $version = new Message\Version(
            70016,
            0,
            (int) (new \DateTimeImmutable())->format('U'),
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
        $node = self::startNode();

        $node->handshake();

        while ($response = $node->recv()) {
            if ('ping' === $response->command) {
                self::assertNotEmpty($response->payload);
                break;
            }
        }

        $node->close();
    }

    public function testValidateHeadersPoW(): void
    {
        $node = self::startNode();
        $node->handshake();

        $node->send(new Message\GetHeaders(70016, 1, self::REGTEST_GENESIS_BLOCK, self::ZERO_HASH_BLOCK));

        ['headers' => $headers] = $node->waitFor('headers');

        $prevBlock = Block::parse(self::stream(hex2bin(self::REGTEST_GENESIS_BLOCK)));
        $blocks    = Message\Headers::parse(self::stream($headers->payload));

        self::assertCount(5, $blocks->blocks);

        foreach ($blocks->blocks as $block) {
            self::assertTrue($block->checkPOW());
            self::assertSame($block->prevBlock, $prevBlock->id());
            $prevBlock = $block;
        }

        $node->close();
    }

    private static function startNode(): Network\SimpleNode
    {
        try {
            return new Network\SimpleNode('127.0.0.1', 18444, false, Network::REGTEST);
        } catch (\RuntimeException) {
            self::markTestSkipped('regtest node is unavailable');
        }
    }
}
