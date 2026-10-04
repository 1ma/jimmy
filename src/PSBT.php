<?php

declare(strict_types=1);

namespace Bitcoin;

final class PSBT implements \Stringable
{
    private const string PSBT_MAGIC_BYTES = "\x70\x73\x62\x74\xff\x00";

    private const string PSBT_GLOBAL_XPUB              = "\x01";
    private const string PSBT_GLOBAL_TX_VERSION        = "\x02";
    private const string PSBT_GLOBAL_FALLBACK_LOCKTIME = "\x03";
    private const string PSBT_GLOBAL_INPUT_COUNT       = "\x04";
    private const string PSBT_GLOBAL_OUTPUT_COUNT      = "\x05";
    private const string PSBT_GLOBAL_TX_MODIFIABLE     = "\x06";
    private const string PSBT_GLOBAL_VERSION           = "\xfb";
    private const string PSBT_GLOBAL_PROPRIETARY       = "\xfc";

    private const string PSBT_IN_NON_WITNESS_UTXO         = "\x00";
    private const string PSBT_IN_WITNESS_UTXO             = "\x01";
    private const string PSBT_IN_PARTIAL_SIG              = "\x02";
    private const string PSBT_IN_SIGHASH_TYPE             = "\x03";
    private const string PSBT_IN_REDEEM_SCRIPT            = "\x04";
    private const string PSBT_IN_WITNESS_SCRIPT           = "\x05";
    private const string PSBT_IN_BIP32_DERIVATION         = "\x06";
    private const string PSBT_IN_FINAL_SCRIPTSIG          = "\x07";
    private const string PSBT_IN_FINAL_SCRIPTWITNESS      = "\x08";
    private const string PSBT_IN_RIPEMD160                = "\x0a";
    private const string PSBT_IN_SHA256                   = "\x0b";
    private const string PSBT_IN_HASH160                  = "\x0c";
    private const string PSBT_IN_HASH256                  = "\x0d";
    private const string PSBT_IN_PREVIOUS_TXID            = "\x0e";
    private const string PSBT_IN_OUTPUT_INDEX             = "\x0f";
    private const string PSBT_IN_SEQUENCE                 = "\x10";
    private const string PSBT_IN_REQUIRED_TIME_LOCKTIME   = "\x11";
    private const string PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = "\x12";
    private const string PSBT_IN_PROPRIETARY              = "\xfc";

    private const string PSBT_OUT_REDEEM_SCRIPT    = "\x00";
    private const string PSBT_OUT_WITNESS_SCRIPT   = "\x01";
    private const string PSBT_OUT_BIP32_DERIVATION = "\x02";
    private const string PSBT_OUT_AMOUNT           = "\x03";
    private const string PSBT_OUT_SCRIPT           = "\x04";
    private const string PSBT_OUT_PROPRIETARY      = "\xfc";

    public function __toString()
    {
        //                           <keylen>   <keytype> [<keydata>]   <valuelen><valuedata>
        return self::PSBT_MAGIC_BYTES."\x01".self::PSBT_GLOBAL_VERSION."\x04\x02\x00\x00\x00";
    }
}
