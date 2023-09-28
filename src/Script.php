<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class Script
{
    /** @var <int|string>[] */
    public array $cmds;

    public function __construct(array $cmds = [])
    {
        $this->cmds = $cmds;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream): self
    {
        $count  = 0;
        $cmds   = [];
        $length = Encoding::decodeVarInt($stream);

        while ($count < $length) {
            $current = fread($stream, 1);
            ++$count;
            $decodedCurrent = gmp_intval(Encoding::fromLE($current));
            if (0x01 <= $decodedCurrent && $decodedCurrent <= 0x4B) {
                $cmds[] = fread($stream, $decodedCurrent);
                $count += $decodedCurrent;
            } elseif (OpCodes::OP_PUSHDATA1->value === $decodedCurrent) {
                $dataLength = gmp_intval(Encoding::fromLE(fread($stream, 1)));
                $cmds[]     = fread($stream, $dataLength);
                $count += $dataLength + 1;
            } elseif (OpCodes::OP_PUSHDATA2->value === $decodedCurrent) {
                $dataLength = gmp_intval(Encoding::fromLE(fread($stream, 2)));
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
                $result .= Encoding::toLE(gmp_init($cmd));
                continue;
            }

            $length = \strlen($cmd);
            if ($length <= 75) {
                $result .= Encoding::toLE(gmp_init($length));
            } elseif ($length < 256) {
                $result .= Encoding::toLE(gmp_init(OpCodes::OP_PUSHDATA1->value));
                $result .= Encoding::toLE(gmp_init($length, 1));
            } elseif ($length <= 520) {
                $result .= Encoding::toLE(gmp_init(OpCodes::OP_PUSHDATA2->value));
                $result .= Encoding::toLE(gmp_init($length, 2));
            } else {
                throw new \RuntimeException('cmd too long: '.$cmd);
            }

            $result .= $cmd;
        }

        return Encoding::encodeVarInt(\strlen($result)).$result;
    }

    public function combine(self $other): self
    {
        return new self(array_merge($this->cmds, $other->cmds));
    }

    public function __toString(): string
    {
        return bin2hex(self::serialize());
    }
}
