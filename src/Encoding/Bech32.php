<?php

declare(strict_types=1);

namespace Bitcoin\Encoding;

use Bitcoin\Tx\Script;

final readonly class Bech32
{
    public const string MAINNET_HRP = 'bc';
    public const string TESTNET_HRP = 'tb';

    private const string BECH32_SEPARATOR = '1';
    private const string BECH32_CHARSET   = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    private const int BECH32_CONST  = 1;
    private const int BECH32M_CONST = 0x2BC830A3;

    public static function segwitEncode(Script $script, string $hrp = self::TESTNET_HRP): string
    {
        if (!$script->isP2WPKH() && !$script->isP2WSH()) {
            throw new \InvalidArgumentException('Only P2WPKH and P2WSH scripts allowed');
        }

        $version  = $script->cmds[0];
        $unpacked = array_values(unpack('C*', $script->cmds[1]));

        $script = array_merge([$version], self::convertBits($unpacked, 8, 5, true));

        return self::encode($script, $hrp, self::BECH32_CONST);
    }

    /**
     * @return array{int, int[]}
     */
    public static function segwitDecode(string $address, string $hrp = self::TESTNET_HRP): array
    {
        [$gotHrp, $data, $spec] = self::decode($address);
        if ($gotHrp !== $hrp) {
            throw new \InvalidArgumentException();
        }

        $decoded = self::convertBits(\array_slice($data, 1), 5, 8, false);
        if (\count($decoded) < 2 || \count($decoded) > 40) {
            throw new \InvalidArgumentException();
        }

        if ($data[0] > 16) {
            throw new \InvalidArgumentException();
        }

        if (0 === $data[0] && !\in_array(\count($decoded), [20, 32], true)) {
            throw new \InvalidArgumentException();
        }

        if (0 === $data[0] && !\in_array($spec, [self::BECH32_CONST, self::BECH32M_CONST], true)) {
            throw new \InvalidArgumentException();
        }

        return [$data[0], $decoded];
    }

    public static function encode(array $data, string $hrp = self::TESTNET_HRP, int $spec = self::BECH32_CONST): string
    {
        $combined = array_merge($data, self::createChecksum($hrp, $data, $spec));

        return $hrp.self::BECH32_SEPARATOR.implode('', array_map(static fn (int $i): string => self::BECH32_CHARSET[$i], $combined));
    }

    /**
     * @return array{string, int[], int}
     */
    public static function decode(string $bech): array
    {
        if (strtolower($bech) !== $bech && strtoupper($bech) !== $bech) {
            throw new \InvalidArgumentException();
        }

        for ($i = 0; $i < \strlen($bech); ++$i) {
            if (\ord($bech[$i]) < 33 || \ord($bech[$i]) > 126) {
                throw new \InvalidArgumentException();
            }
        }

        $bech = strtolower($bech);
        $pos  = strrpos($bech, '1');
        if ($pos < 1 || $pos + 7 > \strlen($bech) || \strlen($bech) > 90) {
            throw new \InvalidArgumentException();
        }

        $hrp = substr($bech, 0, $pos);

        $data = [];
        for ($i = $pos + 1; $i < \strlen($bech); ++$i) {
            if (false === $j = strpos(self::BECH32_CHARSET, $bech[$i])) {
                throw new \InvalidArgumentException();
            }
            $data[] = $j;
        }

        $spec = self::verifyChecksum($hrp, $data);

        return [$hrp, \array_slice($data, 0, -6), $spec];
    }

    /**
     * Based on Pieter Wuille's convertbits function at segwit_addr.py.
     */
    public static function convertBits(array $data, int $fromBits, int $toBits, bool $pad = true): array
    {
        $acc    = 0;
        $bits   = 0;
        $ret    = [];
        $maxv   = (1 << $toBits)                   - 1;
        $maxAcc = (1 << ($fromBits + $toBits - 1)) - 1;

        foreach ($data as $value) {
            if ($value < 0 || $value >> $fromBits) {
                throw new \InvalidArgumentException('Invalid value: '.$value);
            }
            $acc = (($acc << $fromBits) | $value) & $maxAcc;
            $bits += $fromBits;
            while ($bits >= $toBits) {
                $bits -= $toBits;
                $ret[] = ($acc >> $bits) & $maxv;
            }
        }

        if ($pad && $bits) {
            $ret[] = ($acc << ($toBits - $bits)) & $maxv;
        } elseif ($bits >= $fromBits || (($acc << ($toBits - $bits)) & $maxv)) {
            throw new \InvalidArgumentException('Invalid something');
        }

        return $ret;
    }

    private static function createChecksum(string $hrp, array $data, int $spec): array
    {
        $values  = array_merge(self::expandHrp($hrp), $data);
        $polymod = self::polymod(array_merge($values, [0, 0, 0, 0, 0, 0])) ^ $spec;

        $checksum = [];
        for ($i = 0; $i < 6; ++$i) {
            $checksum[] = ($polymod >> 5 * (5 - $i)) & 31;
        }

        return $checksum;
    }

    private static function verifyChecksum(string $hrp, array $data): int
    {
        return self::polymod(array_merge(self::expandHrp($hrp), $data));
    }

    private static function expandHrp(string $hrp): array
    {
        $expansion1 = [];
        $expansion2 = [];
        for ($i = 0; $i < \strlen($hrp); ++$i) {
            $expansion1[] = \ord($hrp[$i]) >> 5;
            $expansion2[] = \ord($hrp[$i]) & 31;
        }

        return array_merge($expansion1, [0], $expansion2);
    }

    private static function polymod(array $values): int
    {
        $generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3];

        $chk = 1;
        foreach ($values as $value) {
            $top = $chk >> 25;
            $chk = ($chk & 0x1FFFFFF) << 5 ^ $value;
            for ($i = 0; $i < 5; ++$i) {
                $chk ^= ($top >> $i) & 1 ? $generator[$i] : 0;
            }
        }

        return $chk;
    }
}
