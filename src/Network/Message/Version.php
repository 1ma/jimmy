<?php

declare(strict_types=1);

namespace Bitcoin\Network\Message;

use Bitcoin\Encoding;
use Bitcoin\Network\Message;

final readonly class Version implements Message
{
    public int $versionNumber;
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
        int $versionNumber,
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
        $this->versionNumber      = $versionNumber;
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

    public function serialize(): string
    {
        $versionNumber      = Encoding::toLE(gmp_init($this->versionNumber), 4);
        $connectionServices = Encoding::toLE(gmp_init($this->connectionServices), 8);
        $timestamp          = Encoding::toLE(gmp_init($this->timestamp), 8);
        $remoteServices     = Encoding::toLE(gmp_init($this->remoteServices), 8);
        $remoteAddress      = str_pad($this->remoteAddress, 16, "\x00");
        $remotePort         = Encoding::toLE(gmp_init($this->remotePort), 2);
        $localServices      = Encoding::toLE(gmp_init($this->localServices), 8);
        $localAddress       = str_pad($this->localAddress, 16, "\x00");
        $localPort          = Encoding::toLE(gmp_init($this->localPort), 2);
        $nonce              = Encoding::toLE(gmp_init($this->nonce), 8);
        $userAgent          = Encoding::encodeVarInt(\strlen($this->userAgent)).$this->userAgent;
        $height             = Encoding::toLE(gmp_init($this->height), 4);
        $relayFlag          = $this->relayFlag ? "\x01" : "\x00";

        return $versionNumber.$connectionServices.$timestamp.$remoteServices.$remoteAddress.$remotePort.$localServices.$localAddress.$localPort.$nonce.$userAgent.$height.$relayFlag;
    }
}
