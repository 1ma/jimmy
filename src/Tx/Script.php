<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

use Bitcoin\ECC\PublicKey;
use Bitcoin\Encoding;
use Bitcoin\Tx\Script\OpCodes;

final readonly class Script
{
    /** @var <int|string>[] */
    public array $cmds;

    private const int P2PKH_HASH_LENGTH  = 20;
    private const int P2WPKH_HASH_LENGTH = 20;
    private const int P2WSH_HASH_LENGTH  = 32;

    public function __construct(array $cmds = [])
    {
        $this->cmds = $cmds;
    }

    public static function opReturn(string $data): self
    {
        return new self([OpCodes::OP_RETURN->value, $data]);
    }

    public static function payToPubKey(string $pubkey): self
    {
        return new self([$pubkey, OpCodes::OP_CHECKSIG->value]);
    }

    public static function payToPubKeyHash(string $h160): self
    {
        if (self::P2PKH_HASH_LENGTH !== \strlen($h160)) {
            throw new \InvalidArgumentException('Invalid hash length');
        }

        return new self([
            OpCodes::OP_DUP->value,
            OpCodes::OP_HASH160->value,
            $h160,
            OpCodes::OP_EQUALVERIFY->value,
            OpCodes::OP_CHECKSIG->value,
        ]);
    }

    public static function payToSegWitV0(string $hash): self
    {
        if (!\in_array(\strlen($hash), [self::P2WPKH_HASH_LENGTH, self::P2WSH_HASH_LENGTH])) {
            throw new \InvalidArgumentException('Invalid hash length');
        }

        return new self([OpCodes::OP_0->value, $hash]);
    }

    public static function payToSegWitV1(PublicKey $pubkey): self
    {
        if (!$pubkey->hasEvenY()) {
            throw new \InvalidArgumentException('Invalid Taproot public key');
        }

        return new self([OpCodes::OP_1->value, $pubkey->xonly()]);
    }

    public static function parseAsString(string $bytes): self
    {
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $bytes);
        rewind($stream);

        try {
            $script = self::parse($stream);
        } finally {
            fclose($stream);
        }

        return $script;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream): self
    {
        $count  = 0;
        $cmds   = [];
        $length = Encoding\VarInt::decode($stream);

        while ($count < $length) {
            $current = fread($stream, 1);
            ++$count;
            $decodedCurrent = gmp_intval(Encoding\Endian::fromLE($current));
            if (0x01 <= $decodedCurrent && $decodedCurrent <= 0x4B) {
                $cmds[] = fread($stream, $decodedCurrent);
                $count += $decodedCurrent;
            } elseif (OpCodes::OP_PUSHDATA1->value === $decodedCurrent) {
                $dataLength = gmp_intval(Encoding\Endian::fromLE(fread($stream, 1)));
                $cmds[]     = fread($stream, $dataLength);
                $count += $dataLength + 1;
            } elseif (OpCodes::OP_PUSHDATA2->value === $decodedCurrent) {
                $dataLength = gmp_intval(Encoding\Endian::fromLE(fread($stream, 2)));
                $cmds[]     = fread($stream, $dataLength);
                $count += $dataLength + 2;
            } else {
                $cmds[] = $decodedCurrent;
            }
        }

        if ($count !== $length) {
            throw new \InvalidArgumentException('Parsing script failed');
        }

        return new self($cmds);
    }

    public function serialize(): string
    {
        $result = '';
        foreach ($this->cmds as $cmd) {
            if (\is_int($cmd)) {
                $result .= Encoding\Endian::toLE(gmp_init($cmd));
                continue;
            }

            $length = \strlen($cmd);
            if ($length <= 75) {
                $result .= Encoding\Endian::toLE(gmp_init($length));
            } elseif ($length < 256) {
                $result .= Encoding\Endian::toLE(gmp_init(OpCodes::OP_PUSHDATA1->value));
                $result .= Encoding\Endian::toLE(gmp_init($length));
            } elseif ($length <= 520) {
                $result .= Encoding\Endian::toLE(gmp_init(OpCodes::OP_PUSHDATA2->value));
                $result .= Encoding\Endian::toLE(gmp_init($length));
            } else {
                throw new \RuntimeException('cmd too long: '.$cmd);
            }

            $result .= $cmd;
        }

        return Encoding\VarInt::encode(\strlen($result)).$result;
    }

    public function combine(self $other): self
    {
        return new self(array_merge($this->cmds, $other->cmds));
    }

    public function isP2SH(): bool
    {
        return 3              === \count($this->cmds)
            && $this->cmds[0] === OpCodes::OP_HASH160->value
            && \is_string($this->cmds[1])
            && 20             === \strlen($this->cmds[1])
            && $this->cmds[2] === OpCodes::OP_EQUAL->value;
    }

    public function isP2WPKH(): bool
    {
        return 2              === \count($this->cmds)
            && $this->cmds[0] === OpCodes::OP_0->value
            && \is_string($this->cmds[1])
            && 20 === \strlen($this->cmds[1]);
    }

    public function isP2WSH(): bool
    {
        return 2              === \count($this->cmds)
            && $this->cmds[0] === OpCodes::OP_0->value
            && \is_string($this->cmds[1])
            && 32 === \strlen($this->cmds[1]);
    }

    public function __toString(): string
    {
        return bin2hex(self::serialize());
    }
}
