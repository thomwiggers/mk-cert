"""The algorithms in use"""
import itertools

signs = [
    ("dilithium2", "Dilithium2"),
]

kems = [
    ("kyber512", "Kyber512"),
]


oids = {var: i for (i, (var, _)) in enumerate(itertools.chain(signs, kems), start=1)}


def get_oid(algorithm):
    oid = oids[algorithm]
    return f"1.3.6.1.4.1.44363.46.{oid}"


def get_oqs_id(algorithm):
    return dict(signs + kems)[algorithm]
