<?php

declare(strict_types=1);

namespace Bitcoin\Network;

use Bitcoin\Encoding;
use Bitcoin\Hashing;
use Bitcoin\Network;

final readonly class Envelope
{
    public Network $network;
    public string $command;
    public string $payload;

    public function __construct(string $command, string $payload, Network $network = Network::TESTNET)
    {
        $this->network = $network;
        $this->command = $command;
        $this->payload = $payload;
    }

    public static function build(Message $message, Network $network = Network::TESTNET): self
    {
        return new self($message->command(), $message->serialize(), $network);
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream, Network $network = Network::TESTNET): self
    {
        $magic = fread($stream, 4);

        if ($network->value !== $magic) {
            throw new \InvalidArgumentException('Invalid magic packet: '.$magic);
        }

        $command = trim(fread($stream, 12));

        $payloadLength = gmp_intval(Encoding::fromLE(fread($stream, 4)));
        $checksum      = fread($stream, 4);

        $payload = 0 === $payloadLength ? '' : fread($stream, $payloadLength);

        if ($checksum !== substr(Hashing::hash256($payload), 0, 4)) {
            throw new \InvalidArgumentException('Invalid checksum');
        }

        return new self($command, $payload, $network);
    }

    public function serialize(): string
    {
        $magic         = $this->network->value;
        $command       = str_pad($this->command, 12, "\x00");
        $payloadLength = Encoding::toLE(gmp_init(\strlen($this->payload)), 4);
        $checksum      = substr(Hashing::hash256($this->payload), 0, 4);

        return $magic.$command.$payloadLength.$checksum.$this->payload;
    }
}
