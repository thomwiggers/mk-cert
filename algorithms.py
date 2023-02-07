"""The algorithms in use"""
import itertools


# for legacy reasons, these are tuples,
# but both sides should be equal up to case.

signs = [
    ("dilithium2", "Dilithium2"),
    ("dilithium3", "Dilithium3"),
    ("dilithium5", "Dilithium5"),
    ("falcon512", "Falcon512"),
    ("falcon1024", "Falcon1024"),
    *[
        (sphincs.lower(), sphincs)
        for sphincs in (
            f"Sphincs{hash}{size}{fs}{kind}"
            for hash in ("Haraka", "Sha256", "Shake256")
            for size in ("128", "192", "256")
            for fs in ("f", "s")
            for kind in ("Simple", "Robust")
        )
    ],
    *[
        (f"pqov{size}", f"Pqov{size}")
        for size in ("1616044", "25611244", "25618472", "25614496")
    ],
    ("xmss", "XMSS"),
]

kems = [
    ("kyber512", "Kyber512"),
    ("kyber768", "Kyber768"),
    ("kyber1024", "Kyber1024"),
    *[
        (f"classicmceliece{size}", f"ClassicMcEliece{size}")
        for size in (
            "348864",
            "348864f",
            "460896",
            "460896f",
            "6688128",
            "6688128f",
            "6960119",
            "6960119f",
            "8192128",
            "8192128f",
        )
    ],
    ("ntruprimesntrup761", "NtruPrimeSntrup761"),
    *[
        (f"frodokem{size}{alg}", f"FrodoKem{size.title()}{alg.title()}")
        for size in ("640", "976", "1344")
        for alg in ("aes", "shake")
    ],
    *[
        (f"sikep{size}{compressed}", f"SikeP{size}{compressed.title()}")
        for size in ("434", "503", "610", "751")
        for compressed in ("", "compressed")
    ],
    ("bikel1fo", "BikeL1Fo"),
    ("bikel3fo", "BikeL3Fo"),
    *[(f"hqc{size}", f"Hqc{size}") for size in ["128", "192", "256"]],
]


oids = {var: i for (i, (var, _)) in enumerate(itertools.chain(signs, kems), start=1)}


def get_oid(algorithm):
    oid = oids[algorithm]
    return f"1.3.6.1.4.1.44363.46.{oid}"


def get_oqs_id(algorithm):
    return dict(signs + kems)[algorithm]


def is_sigalg(algorithm: str) -> bool:
    return algorithm.lower() in dict(signs).keys()
