<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

final readonly class Signature
{
    public \GMP $r;
    public \GMP $s;

    public function __construct(\GMP $r, \GMP $s)
    {
        $this->r = $r;
        $this->s = $s;
    }

    public static function parse(string $der): self
    {
        // TODO
        return new self(gmp_init(0), gmp_init(0));
    }

    public function der(): string
    {
        $rBytes = gmp_export($this->r);
        if (unpack('C', $rBytes[0])[1] & 0x80) {
            $rBytes = "\x00".$rBytes;
        }

        $rLen   = \strlen($rBytes);
        $rBytes = "\x02".pack('C', $rLen).$rBytes;

        $sBytes = gmp_export($this->s);
        if (unpack('C', $sBytes[0])[1] & 0x80) {
            $sBytes = "\x00".$sBytes;
        }

        $sLen   = \strlen($sBytes);
        $sBytes = "\x02".pack('C', $sLen).$sBytes;

        return "\x30".pack('C', 2 + $rLen + 2 + $sLen).$rBytes.$sBytes;
    }

    public function __toString(): string
    {
        return sprintf('Signature(%s,%s)', gmp_strval($this->r, 16), gmp_strval($this->s, 16));
    }
}
