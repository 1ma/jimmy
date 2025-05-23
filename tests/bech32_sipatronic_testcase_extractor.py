import json
import os
import sys

test_vectors = [
    "VALID_BECH32", "VALID_BECH32M",
    "INVALID_BECH32", "INVALID_BECH32M",
    "VALID_ADDRESS", "INVALID_ADDRESS",
    "INVALID_ADDRESS_ENC"
]

path = os.path.join(os.path.dirname(__file__), "../vendor/sipa/bech32/ref/python")
sys.path.insert(0, path)

import tests

print(json.dumps({vector: getattr(tests, vector) for vector in test_vectors}))
