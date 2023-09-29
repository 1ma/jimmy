<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

final readonly class Signature
{
    public \GMP $r;
    public \GMP $s;

    // 1 (int marker 02) + 1 (r length) + 1 (padding 00) + 32 bytes + 1 (int marker 02) + 1 (s length) + 1 (padding 00) + 32 bytes
    private const MAX_DER_LENGTH = 70;

    public function __construct(\GMP $r, \GMP $s)
    {
        $this->r = $r;
        $this->s = $s;
    }

    public static function parse(string $der): static
    {
        $derLen = \strlen($der);
        if ($derLen < 2 || "\x30" !== $der[0]) {
            throw new \InvalidArgumentException('Invalid DER signature');
        }

        $dataLen = unpack('C', $der[1])[1];
        if ($dataLen > self::MAX_DER_LENGTH || \strlen(substr($der, 2, $dataLen)) !== $derLen - 2) {
            throw new \InvalidArgumentException('Invalid DER signature');
        }

        $rLen = unpack('C', $der[3])[1];
        if ("\x02" !== $der[2] || (32 !== $rLen && 33 !== $rLen)) {
            throw new \InvalidArgumentException('Invalid DER signature');
        }

        $sOffset = 4 + $rLen;
        $sLen    = unpack('C', $der[$sOffset + 1])[1];
        if ("\x02" !== $der[$sOffset] || (32 !== $sLen && 33 !== $sLen) || $dataLen !== 4 + $rLen + $sLen) {
            throw new \InvalidArgumentException('Invalid DER signature');
        }

        return new self(gmp_import(substr($der, 4, $rLen)), gmp_import(substr($der, $sOffset + 2, $sLen)));
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
