# Writes sha3_random.txt: SHA3-256/512 and SHAKE128/256 outputs computed by Python's hashlib (an
# independent Keccak implementation) for pseudo-random messages whose lengths straddle the rates
# (72, 136, 168 bytes) and their multiples, and SHAKE outputs longer than one block.
#   python -I tests/vectors/pq/sha3_random.py tests/vectors/pq/sha3_random.txt
import hashlib
import random
import sys

rng = random.Random(20261025)
lens = sorted(set([0, 1, 71, 72, 73, 135, 136, 137, 167, 168, 169, 271, 272, 273, 335, 336, 337, 503, 504, 505,
                   1000, 2047, 4096] + [rng.randrange(0, 3000) for _ in range(20)]))
with open(sys.argv[1], "w", newline="\n") as f:
    f.write("# hashlib (Python %s) reference: alg msg output; alg = 256|512 (SHA3) or s128|s256 (SHAKE)\n"
            % sys.version.split()[0])
    for n in lens:
        m = bytes(rng.randrange(256) for _ in range(n))
        mh = m.hex() or "-"
        f.write("256 %s %s\n" % (mh, hashlib.sha3_256(m).hexdigest()))
        f.write("512 %s %s\n" % (mh, hashlib.sha3_512(m).hexdigest()))
        for bits, outlen in ((128, rng.choice([1, 32, 167, 168, 169, 500])), (256, rng.choice([1, 64, 135, 136, 137, 700]))):
            x = hashlib.shake_128(m) if bits == 128 else hashlib.shake_256(m)
            f.write("s%d %s %s\n" % (bits, mh, x.hexdigest(outlen)))
