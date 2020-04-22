import sys
from encoder import oids, signs, camel_to_snake, kems

if sys.argv[1] == "signs":

    for alg in signs:
        oid_offset = oids[alg]
        alg = camel_to_snake(alg).upper()
        oid_bytes = 0xFE00 + oid_offset
        print(
            rf"""
const {alg}_ID: AlgorithmIdentifier = AlgorithmIdentifier {{
    asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\x{oid_bytes>>8:02X}\x{oid_bytes&0xFF:02X}"
}};

/// {alg} signature
pub static {alg}: SignatureAlgorithm = SignatureAlgorithm {{
    public_key_alg_id: {alg}_ID,
    signature_alg_id: {alg}_ID,
    verification_alg: &signature::{alg},
}};
""")

else:
    for name in kems:
        oid_offset = oids[name]
        oid_bytes = 0xFE00 + oid_offset
        print(rf"""
const {name.upper()}_ID: AlgorithmIdentifier = AlgorithmIdentifier {{
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\x{oid_bytes>>8:02X}\x{oid_bytes&0xFF:02X}"
}};

/// { name } kem
pub static {name.upper()}: KemAlgorithm = KemAlgorithm {{
    public_key_alg_id: {name.upper()}_ID,
    kem: &ring::agreement::{name.upper()},
}};
    """)

    for name in kems:
        print(f"    get_kem!({name.upper()}, algorithm_id);")
