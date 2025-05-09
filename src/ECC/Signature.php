<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

use Bitcoin\Encoding;

final readonly class Signature
{
    public \GMP $r;
    public \GMP $s;

    public function __construct(\GMP $r, \GMP $s, bool $allowLargeS = false)
    {
        if (!$allowLargeS && $s > S256Params::Ndiv2()) {
            throw new \InvalidArgumentException('s is larger than N/2');
        }

        $this->r = $r;
        $this->s = $s;
    }

    /**
     * Validation code based on the IsValidSignatureEncoding function
     * defined in BIP-66.
     */
    public static function parse(string $der, bool $allowLargeS = false): self
    {
        $derLen = \strlen($der);

        if ($derLen < 8 || $derLen > 72) {
            throw new \InvalidArgumentException('Invalid DER signature: Minimum and maximum size constraints.');
        }

        if ("\x30" != $der[0]) {
            throw new \InvalidArgumentException('Invalid DER signature: A signature is of type 0x30 (compound).');
        }

        if (unpack('C', $der[1])[1] != $derLen - 2) {
            throw new \InvalidArgumentException('Invalid DER signature: Make sure the length covers the entire signature.');
        }

        // Extract the length of the R element.
        $lenR = unpack('C', $der[3])[1];

        if (5 + $lenR >= $derLen) {
            throw new \InvalidArgumentException('Invalid DER signature: Make sure the length of the S element is still inside the signature.');
        }

        // Extract the length of the S element.
        $lenS = unpack('C', $der[5 + $lenR])[1];

        if ($lenR + $lenS + 6 !== $derLen) {
            throw new \InvalidArgumentException('Invalid DER signature: Verify that the length of the signature matches the sum of the length of the elements.');
        }

        if ("\x02" != $der[2]) {
            throw new \InvalidArgumentException('Invalid DER signature: Check whether the R element is an integer.');
        }

        if (0 === $lenR) {
            throw new \InvalidArgumentException('Invalid DER signature: Zero-length integers are not allowed for R.');
        }

        if (unpack('C', $der[4])[1] & 0x80) {
            throw new \InvalidArgumentException('Invalid DER signature: Negative numbers are not allowed for R.');
        }

        if ($lenR > 1 && "\x00" === $der[4] && !(unpack('C', $der[5])[1] & 0x80)) {
            throw new \InvalidArgumentException('Invalid DER signature: Null bytes at the start of R are not allowed, unless R would otherwise be interpreted as a negative number.');
        }

        if ("\x02" != $der[$lenR + 4]) {
            throw new \InvalidArgumentException('Invalid DER signature: Check whether the S element is an integer.');
        }

        if (0 === $lenS) {
            throw new \InvalidArgumentException('Invalid DER signature: Zero-length integers are not allowed for S.');
        }

        if (unpack('C', $der[$lenR + 6])[1] & 0x80) {
            throw new \InvalidArgumentException('Invalid DER signature: Negative numbers are not allowed for S.');
        }

        if ($lenS > 1 && "\x00" === $der[$lenR + 6] && !(unpack('C', $der[$lenR + 7])[1] & 0x80)) {
            throw new \InvalidArgumentException('Invalid DER signature: Null bytes at the start of S are not allowed, unless S would otherwise be interpreted as a negative number.');
        }

        return new self(gmp_import(substr($der, 4, $lenR)), gmp_import(substr($der, 6 + $lenR, $lenS)), $allowLargeS);
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

    /**
     * BIP-340 fixed length encoding of the signature.
     */
    public function bip340(): string
    {
        return Encoding\Endian::toBE($this->r, 32).Encoding\Endian::toBE($this->s, 32);
    }

    public function __toString(): string
    {
        return \sprintf('Signature(%s,%s)', gmp_strval($this->r, 16), gmp_strval($this->s, 16));
    }
}
