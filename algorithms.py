"""The algorithms in use"""
import itertools

signs = [
    ("dilithium2", "Dilithium2"),
    ("dilithium3", "Dilithium3"),
    ("dilithium5", "Dilithium5"),
    ("falcon512", "Falcon512"),
    ("falcon1024", "Falcon1024"),
    ("rainbowiclassic", "RainbowIClassic"),
    ("rainbowicircumzenithal", "RainbowICircumzenithal"),
    ("rainbowicompressed", "RainbowICompressed"),
    ("rainbowiiiclassic", "RainbowIiiClassic"),
    ("rainbowiiicircumzenithal", "RainbowIiiCircumzenithal"),
    ("rainbowiiicompressed", "RainbowIiiCompressed"),
    ("rainbowvclassic", "RainbowVClassic"),
    ("rainbowvcircumzenithal", "RainbowVCircumzenithal"),
    ("rainbowvcompressed", "RainbowVCompressed"),
    *[(sphincs.lower(), sphincs) for sphincs in (
        f"Sphincs{hash}{size}{fs}{kind}"
        for hash in ("Haraka", "Sha256", "Shake256")
        for size in ("128", "192", "256")
        for fs in ("f", "s")
        for kind in ("Simple", "Robust")
    )],
]

kems = [
    ("kyber512", "Kyber512"),
    ("kyber768", "Kyber768"),
    ("kyber1024", "Kyber1024"),
    *[
        (f"mceliece{size}", f"ClassicMcEliece{size}")
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
    ("lightsaber", "Lightsaber"),
    ("saber", "Saber"),
    ("firesaber", "Firesaber"),
    ("ntruhps2048509", "NtruHps2048509"),
    ("SidhP434", "SidhP434"),
]


oids = {var: i for (i, (var, _)) in enumerate(itertools.chain(signs, kems), start=1)}


def get_oid(algorithm):
    oid = oids[algorithm]
    return f"1.3.6.1.4.1.44363.46.{oid}"


def get_oqs_id(algorithm):
    return dict(signs + kems)[algorithm]
