<?php

declare(strict_types=1);

namespace Bitcoin\Network;

use Bitcoin\Encoding;
use Bitcoin\Hashing;

final readonly class Envelope
{
    public const MAINNET_MAGIC = "\xf9\xbe\xb4\xd9";
    public const TESTNET_MAGIC = "\x0b\x11\x09\x07";

    public string $magic;
    public string $command;
    public string $payload;

    public function __construct(string $command, string $payload, bool $testnet = true)
    {
        $this->magic   = $testnet ? self::TESTNET_MAGIC : self::MAINNET_MAGIC;
        $this->command = $command;
        $this->payload = $payload;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream, bool $testnet = true): self
    {
        $magic = fread($stream, 4);

        if (($testnet && self::TESTNET_MAGIC !== $magic) || self::MAINNET_MAGIC !== $magic) {
            throw new \InvalidArgumentException('Invalid magic packet: '.$magic);
        }

        $command = trim(fread($stream, 12));

        $payloadLength = gmp_intval(Encoding::fromLE(fread($stream, 4)));
        $checksum      = fread($stream, 4);

        $payload = $payloadLength > 0 ? fread($stream, $payloadLength) : '';

        if ($checksum !== substr(Hashing::hash256($payload), 0, 4)) {
            throw new \InvalidArgumentException('Invalid checksum');
        }

        return new self($command, $payload, $testnet);
    }

    public function serialize(): string
    {
        $command       = str_pad($this->command, 12, "\x00");
        $payloadLength = Encoding::toLE(gmp_init(\strlen($this->payload)), 4);
        $checksum      = substr(Hashing::hash256($this->payload), 0, 4);

        return $this->magic.$command.$payloadLength.$checksum.$this->payload;
    }
}
