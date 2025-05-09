<?php

declare(strict_types=1);

namespace Bitcoin\Network\Message;

use Bitcoin\Encoding;
use Bitcoin\Network\Message;

final readonly class Version implements Message
{
    public int $protocolVersion;
    public int $connectionServices;
    public int $timestamp;

    public int $remoteServices;
    public string $remoteAddress;
    public int $remotePort;

    public int $localServices;
    public string $localAddress;
    public int $localPort;

    public int $nonce;
    public string $userAgent;
    public int $height;
    public bool $relayFlag;

    public function __construct(
        int $protocolVersion,
        int $connectionServices,
        int $timestamp,
        int $remoteServices,
        string $remoteAddress,
        int $remotePort,
        int $localServices,
        string $localAddress,
        int $localPort,
        int $nonce,
        string $userAgent,
        int $height,
        bool $relayFlag,
    ) {
        $this->protocolVersion    = $protocolVersion;
        $this->connectionServices = $connectionServices;
        $this->timestamp          = $timestamp;
        $this->remoteServices     = $remoteServices;
        $this->remoteAddress      = $remoteAddress;
        $this->remotePort         = $remotePort;
        $this->localServices      = $localServices;
        $this->localAddress       = $localAddress;
        $this->localPort          = $localPort;
        $this->nonce              = $nonce;
        $this->userAgent          = $userAgent;
        $this->height             = $height;
        $this->relayFlag          = $relayFlag;
    }

    public function command(): string
    {
        return 'version';
    }

    public static function parse($stream): self
    {
        throw new \LogicException('not implemented');
    }

    public function serialize(): string
    {
        $protocolVersion    = Encoding\Endian::toLE(gmp_init($this->protocolVersion), 4);
        $connectionServices = Encoding\Endian::toLE(gmp_init($this->connectionServices), 8);
        $timestamp          = Encoding\Endian::toLE(gmp_init($this->timestamp), 8);
        $remoteServices     = Encoding\Endian::toLE(gmp_init($this->remoteServices), 8);
        $remoteAddress      = str_pad($this->remoteAddress, 16, "\x00");
        $remotePort         = Encoding\Endian::toLE(gmp_init($this->remotePort), 2);
        $localServices      = Encoding\Endian::toLE(gmp_init($this->localServices), 8);
        $localAddress       = str_pad($this->localAddress, 16, "\x00");
        $localPort          = Encoding\Endian::toLE(gmp_init($this->localPort), 2);
        $nonce              = Encoding\Endian::toLE(gmp_init($this->nonce), 8);
        $userAgent          = Encoding\VarInt::encode(\strlen($this->userAgent)).$this->userAgent;
        $height             = Encoding\Endian::toLE(gmp_init($this->height), 4);
        $relayFlag          = $this->relayFlag ? "\x01" : "\x00";

        return $protocolVersion.$connectionServices.$timestamp.$remoteServices.$remoteAddress.$remotePort.$localServices.$localAddress.$localPort.$nonce.$userAgent.$height.$relayFlag;
    }
}
