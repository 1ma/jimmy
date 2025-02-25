# Programming Bitcoin

[![CI](https://github.com/1ma/jimmy/actions/workflows/ci.yml/badge.svg)](https://github.com/1ma/jimmy/actions/workflows/ci.yml)
[![Coverage](https://scrutinizer-ci.com/g/1ma/jimmy/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/1ma/jimmy/?branch=master)

Jimmy Song's [Programming Bitcoin](https://github.com/jimmysong/programmingbitcoin/) code implemented in PHP.

```shell
composer require uma/jimmy:dev-master
```

## Disclaimer

This is toy grade code meant to learn concepts, not to be used in real projects that reach production.

It's not performant, it's not tested extensively, and it hasn't been reviewed. If you use it on mainnet you
will possibly leak private keys, create transactions with invalid UTXOs that cannot be spent, etc.

To emphasize this I won't tag any release, and I don't promise any kind of backward compatibility.
To further emphasize it the library assumes that it runs on testnet by default instead of mainnet.


## Book Chapters Implemented

- [X] Chapter 1: Finite Fields
- [X] Chapter 2: Elliptic Curves
- [X] Chapter 3: Elliptic Curve Cryptography
- [X] Chapter 4: Serialization
- [X] Chapter 5: Transactions
- [X] Chapter 6: Script
- [X] Chapter 7: Transaction Creation and Validation
- [X] Chapter 8: Pay-to-Script Hash
- [X] Chapter 9: Blocks
- [X] Chapter 10: Networking
- [ ] Chapter 11: Simplified Payment Verification
- [ ] Chapter 12: Bloom Filters
- [X] Chapter 13: SegWit


## Other Areas of Interest

- [ ] [BIP-0032]: Hierarchical Deterministic Wallets
- [ ] [BIP-0039]: Mnemonic code for generating deterministic keys
- [ ] [BIP-0044]: Multi-Account Hierarchy for Deterministic Wallets
- [ ] [BIP-0084]: Derivation scheme for P2WPKH based accounts
- [ ] [BIP-0086]: Key Derivation for Single Key P2TR Outputs
- [ ] [BIP-0173]: Base32 address format for native v0-16 witness outputs
- [ ] [BIP-0322]: Generic Signed Message Format
- [X] [BIP-0325]: Signet
- [ ] [BIP-0340]: Schnorr Signatures for secp256k1
- [ ] [BIP-0341]: Taproot
- [ ] [BIP-0342]: Validation of Taproot Scripts
- [ ] [BIP-0350]: Bech32m format for v1+ witness addresses
- [ ] [BIP-0370]: Partially Signed Bitcoin Transaction Format Version 2
- [ ] [BIP-0371]: Taproot Fields for PSBT
- [X] [Wycheproof compliance]

## How

Implementing the code related to ECC requires doing math operations on 256-bit integers, that's why the book uses Python.

PHP, like most programming languages, only has 32 or 64-bit integers that match the machine's word size.
However, the language has a native binding to [libgmp](https://www.php.net/manual/en/book.gmp.php) that provides support for
representing and doing math on arbitrarily large integers with bearable (though not adequate) performance, just like Python.

To reiterate, this code is certainly vulnerable to timing side-channel attacks and other problems, do not use it in production.


[BIP-0032]: https://bips.xyz/32
[BIP-0039]: https://bips.xyz/39
[BIP-0044]: https://bips.xyz/44
[BIP-0084]: https://bips.xyz/84
[BIP-0086]: https://bips.xyz/86
[BIP-0173]: https://bips.xyz/173
[BIP-0322]: https://bips.xyz/322
[BIP-0325]: https://bips.xyz/325
[BIP-0340]: https://bips.xyz/340
[BIP-0341]: https://bips.xyz/341
[BIP-0342]: https://bips.xyz/342
[BIP-0350]: https://bips.xyz/350
[BIP-0370]: https://bips.xyz/370
[BIP-0371]: https://bips.xyz/371
[Wycheproof compliance]: https://github.com/1ma/jimmy/pull/1
