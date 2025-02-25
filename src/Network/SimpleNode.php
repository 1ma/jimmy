<?php

declare(strict_types=1);

namespace Bitcoin\Network;

use Bitcoin\Network;

final readonly class SimpleNode
{
    public string $address;
    public int $port;
    public bool $logging;
    public Network $network;

    /** @var resource */
    private mixed $socket;

    public function __construct(string $address, int $port, bool $logging, Network $network = Network::TESTNET)
    {
        $this->address = $address;
        $this->port    = $port;
        $this->logging = $logging;
        $this->network = $network;

        $this->socket = @fsockopen($this->address, $this->port);

        if (false === $this->socket) {
            throw new \RuntimeException("could not establish a TCP connection to {$this->address}:{$this->port}");
        }

        if ($this->logging) {
            fwrite(\STDERR, "Established TCP connection to {$this->address}:{$this->port}\n");
        }
    }

    public function send(Message $message): void
    {
        fwrite($this->socket, Envelope::build($message, $this->network)->serialize());

        if ($this->logging) {
            $hex = empty($message->serialize()) ? '(empty payload)' : bin2hex($message->serialize());
            fwrite(\STDERR, "Sent '{$message->command()}' message: {$hex}\n");
        }
    }

    public function recv(): Envelope
    {
        $response = Envelope::parse($this->socket, $this->network);

        if ($this->logging) {
            $hex = empty($response->payload) ? '(empty payload)' : bin2hex($response->payload);
            fwrite(\STDERR, "Received '{$response->command}' message: {$hex}\n");
        }

        return $response;
    }

    public function handshake(): void
    {
        $this->send(new Message\Version(
            70016,
            0,
            (int) new \DateTimeImmutable()->format('U'),
            0,
            '',
            0,
            0,
            '',
            0,
            random_int(0, \PHP_INT_MAX),
            '/Programming Bitcoin in PHP/',
            0,
            false
        ));

        $versionReceived = false;
        $verAckReceived  = false;
        while ($response = $this->recv()) {
            if ('version' === $response->command) {
                $versionReceived = true;
                $this->send(new Message\VerAck());
            }

            if ('verack' === $response->command) {
                $verAckReceived = true;
            }

            if ($versionReceived && $verAckReceived) {
                break;
            }
        }
    }

    public function close(): void
    {
        fclose($this->socket);

        if ($this->logging) {
            fwrite(\STDERR, "Closed TCP connection to {$this->address}:{$this->port}\n");
        }
    }
}
