#! /usr/bin/env sage
from __future__ import annotations
from random import randint
from sage.all import *
from sage.schemes.elliptic_curves.ell_point import EllipticCurvePoint
from hashlib import sha256
import json
import subprocess
import argparse
from multipledispatch import dispatch


def millerTest(d, n):
    a = 2 + randint(1, n - 4)

    x = pow(a, d, n)

    if x == 1 or x == n - 1:
        return True

    while d != n - 1:
        x = (x * x) % n
        d *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True

    return False


def isPrime(n, k):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    d = n - 1
    while d % 2 == 0:
        d //= 2

    for i in range(k):
        if millerTest(d, n) == False:
            return False

    return True


def gen_prime(n_bits) -> int:
    n_iter = 25
    while True:
        p = randint(2 ** (n_bits - 1), 2 ** (n_bits) - 1)
        p = p | 1

        if isPrime(p, n_iter):
            return p


class EC:
    @dispatch(int, int, int, int, int)
    def __init__(
        self,
        prime: int,
        a: int,
        b: int,
        b_x: int,
        b_y: int,
    ):
        self.prime = prime
        self.a = a
        self.b = b
        self.sage_ec = EllipticCurve(Zmod(prime), [a, b])
        self.sage_B = self.sage_ec(b_x, b_y)
        self.B = ECPoint(self, b_x, b_y)

    @dispatch(int, int)
    def __init__(
        self,
        n_bits: int,
        ord_b_ratio: int,
    ):
        self.gen_ecdh(n_bits, ord_b_ratio)
        self.B = ECPoint(self, self.sage_B.xy()[0], self.sage_B.xy()[1])

    @dispatch(str)
    def __init__(self, filename: str):
        with open(filename, "r") as file:
            params = json.load(file)

        self.__init__(
            params["curve_p"],
            params["curve_a"],
            params["curve_b"],
            params["sub_generator"]["x"],
            params["sub_generator"]["y"],
        )

    # generates a valid elliptic curve and B a point generating a big sub-group
    def gen_ecdh(self, n_bits, ord_b_ratio):
        self.prime = gen_prime(n_bits)
        print(f"Prime's value : {self.prime}")

        while True:
            change_curve = False
            self.a = randint(0, self.prime - 1)
            self.b = randint(0, self.prime - 1)

            F = Zmod(self.prime)
            self.sage_ec = EllipticCurve(F, [self.a, self.b])

            # Verify that N is not smooth, go again otherwise
            N = self.sage_ec.order()
            r = max(factor(N))
            if r[0] <= N // ord_b_ratio:  # parametrized arbitrary value of smoothness
                print(f"N (cardinality of the curve): {N} is smooth,", end="")
                change_curve = True

            i = 0
            B_order = -1
            while B_order != r[0] and not change_curve:
                self.sage_B = self.sage_ec.random_point()
                B_order = self.sage_B.order()
                print(f"Choosing B, try {i}/{1000}, B order > r : {B_order > r[0]}")
                if B_order == r[0]:
                    break

                # Try to get a generator with a less random way. ChatGPT:
                #   If B has order n, to get a generator of a sub-group of <B> of order p with n = pq
                #   you can try to calculate qB and verify that qB has order p
                B_p = ECPoint(self, self.sage_B.xy()[0], self.sage_B.xy()[1])
                B_p = B_p * (B_order // r[0])

                self.sage_B = B_p.to_sage()
                B_order = self.sage_B.order()

                i += 1
                if i > 1e3:
                    print("Too many tries to find a correct B,", end="")
                    change_curve = True

            if change_curve:
                print(" changing curve.")
                continue

            print(f"Valeur de r: {r}")
            print(f"Ordre de B: {self.sage_B.order()}")
            break

    # returns the public key from x the private key
    def compPubKey(self, x: int) -> ECPoint:
        return self.B * x

    def save_to_file(self, filename: str):
        values = {
            "curve_p": self.prime,
            "curve_a": self.a,
            "curve_b": self.b,
            "sub_generator": {"x": int(self.B.x), "y": int(self.B.y)},
        }

        with open(filename, "w") as file:
            json.dump(values, file)

        print(f"Elliptic curve parameters saved to '{filename}'")


class ECPoint:
    def __init__(self, ec: EC, x, y):
        self.ec = ec
        self.ring = IntegerModRing(self.ec.prime)
        self.x = self.ring(x)
        self.y = self.ring(y)

    def to_sage(self) -> EllipticCurvePoint:
        return self.ec.sage_ec(self.x, self.y)

    def __add__(self, other: ECPoint) -> ECPoint:
        x1 = self.x
        y1 = self.y
        x2 = other.x
        y2 = other.y

        # x1, y1, x2 and y2 are sage RingInteger with a prime cardinality, so division should not fail and is done the right way
        x = ((y2 - y1) / (x2 - x1)) ** 2 - x1 - x2
        y = -y1 + (x1 - x) * (y2 - y1) / (x2 - x1)

        # Just to be sure, this will throw an error if the calculated point is not on the curve
        # self.ec.sage_ec(x, y)

        return ECPoint(self.ec, x, y)

    # Calculates 2*self
    def times_2(self) -> ECPoint:
        x1 = self.x
        y1 = self.y

        # x1 and y1 are sage RingInteger with a prime cardinality, so division should not fail and is done the right way
        x = ((3 * x1**2 + self.ec.a) / (2 * y1)) ** 2 - 2 * x1
        y = -y1 + (x1 - x) * (3 * x1**2 + self.ec.a) / (2 * y1)

        # Just to be sure, this will throw an error if the calculated point is not on the curve
        # self.ec.sage_ec(x, y)

        return ECPoint(self.ec, x, y)

    # Does the calculation on the elliptic curve x*self with x positive integer
    def times(self, x: int) -> ECPoint:
        assert x > 0

        res = copy(self)
        # Square and multiple in additive group
        while x != 1:
            if x % 2 == 0:
                res = res.times_2()
                x = x // 2
            else:
                res = res + res.times_2()
                x = (x - 1) // 2

        return res

    @dispatch(int)
    def __mul__(self, x: int) -> ECPoint:
        return self.times(x)

    @dispatch(Integer)
    def __mul__(self, x: Integer) -> ECPoint:
        return self.times(x)


def HMAC(k: int, m: int):
    def int_to_bytes(v: int):
        return v.to_bytes((v.bit_length() + 7) // 8, "big")

    opad = 0x5C
    ipad = 0x36

    hasher = sha256()
    first = int_to_bytes(k ^ opad)

    hasher.update(int_to_bytes(k ^ ipad))
    hasher.update(int_to_bytes(m))
    second = hasher.digest()

    hasher = sha256()
    hasher.update(first)
    hasher.update(second)
    return hasher.digest()


def create_ecdh_keypair(ec: EC, filename):
    x_a = randint(ec.prime // 2, ec.prime - 1)
    x_aB = ec.compPubKey(x_a)
    values = {"x": int(x_a), "xB": {"x": int(x_aB.x), "y": int(x_aB.y)}}

    with open(filename, "w") as file:
        json.dump(values, file)


def create_encrypting_key(x_own: int, x_otherB: ECPoint, key_file: str):
    shared_secret = int((x_otherB * x_own).x)
    key = HMAC(shared_secret, 0)

    with open(key_file, "w") as file:
        file.write(key.hex())


def create_encrypting_key_from_files(
    curve_file, private_key_file, other_key_file, out_filename
):
    ec = EC(curve_file)
    with open(private_key_file, "r") as file:
        d = json.load(file)
        x_own = d["x"]

    with open(other_key_file, "r") as file:
        d = json.load(file)
        x_otherB = ECPoint(ec, d["xB"]["x"], d["xB"]["y"])

    create_encrypting_key(x_own, x_otherB, out_filename)


def read_key_ivt(keyf, ivf):
    with open(keyf, "r") as file:
        key = bytes.fromhex(file.read())
    with open(ivf, "r") as file:
        iv = bytes.fromhex(file.read())

    return key, iv


def ciffer(key, IV, filename, out_filename):
    command = f"openssl aes-256-cbc -e -in {filename} -out {out_filename} -K {key.hex()} -iv {IV.hex()}"
    subprocess.run(command, shell=True)


def deciffer(key, IV, filename, out_filename):
    command = f"openssl aes-256-cbc -d -in {filename} -out {out_filename} -K {key.hex()} -iv {IV.hex()}"
    subprocess.run(command, shell=True)


if __name__ == "__main__":
    # create_key()
    # ciffer(key, IV, "clair.txt", "chiffre.txt")
    # deciffer(key, IV, "chiffre.txt", "dechiffre.txt")

    parser = argparse.ArgumentParser(
        prog="ecdh",
        description="Helper for the ECDH protocol with AES256CBC encryption",
    )

    parser.add_argument(
        "command",
        choices=["genprivkey", "encrypt", "decrypt", "gencurve", "genenckey"],
        help="""gencurve [-o OUTFILE] <number_of_bits> <smoothness criterion> | 
                genprivkey [-o OUTFILE] <curvefile> | 
                genenckey [-o OUTFILE] <own_private_key_file> <other_public_keyfile> <curve_file> | 
                encrypt [-o OUTFILE] <plaintextfile> <sharedkeyfile> <IV_file> | 
                decrypt [-o OUTFILE] <ciffertextfile> <sharedkeyfile> <IV_file>""",
    )
    parser.add_argument("-o", "--outfile", default=None)
    parser.add_argument(
        "argument", nargs="*", help="List of arguments for each command"
    )

    args = parser.parse_args()

    match args.command:
        case "gencurve":
            n_bits = 256 if (len(args.argument) == 0) else int(args.argument[0])
            smoothness_crit = (
                100000 if (len(args.argument) <= 1) else int(args.argument[1])
            )
            print(f"Generating curve with a {n_bits} bits prime ...")
            curve = EC(n_bits, smoothness_crit)
            f = "curve.json" if (args.outfile == None) else args.outfile
            curve.save_to_file(f)

        case "genprivkey":
            f = "curve.json" if (len(args.argument) == 0) else args.argument[0]
            o = "privkey.json" if (args.outfile == None) else args.outfile
            curve = EC(f)
            create_ecdh_keypair(curve, o)

        case "genenckey":
            o = "key.txt" if (args.outfile == None) else args.outfile
            own = args.argument[0]
            other = args.argument[1]
            curve = args.argument[2]
            create_encrypting_key_from_files(curve, own, other, o)

        case "encrypt":
            o = "encrypted.txt" if (args.outfile == None) else args.outfile
            ptf = args.argument[0]
            keyf = args.argument[1]
            ivf = args.argument[2]
            key, iv = read_key_ivt(keyf, ivf)
            ciffer(key, iv, ptf, o)

        case "decrypt":
            o = "decrypted.txt" if (args.outfile == None) else args.outfile
            ptf = args.argument[0]
            keyf = args.argument[1]
            ivf = args.argument[2]
            key, iv = read_key_ivt(keyf, ivf)
            deciffer(key, iv, ptf, o)
