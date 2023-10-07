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
- [ ] Chapter 10: Networking
- [ ] Chapter 11: Simplified Payment Verification
- [ ] Chapter 12: Bloom Filters
- [X] Chapter 13: SegWit


## How

Implementing the code related to ECC requires doing math operations on 256-bit integers, that's why the book uses Python.

PHP, like most programming languages, only has 32 or 64-bit integers that match the machine's word size.
However, it has a native binding to [libgmp](https://www.php.net/manual/en/book.gmp.php) that provides support for
representing and doing math on arbitrarily large integers with bearable (though not adequate) performance, just like Python.
